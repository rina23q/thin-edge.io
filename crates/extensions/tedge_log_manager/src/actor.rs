use async_trait::async_trait;
use http::status::StatusCode;
use log::error;
use log::info;
use log_manager::LogPluginConfig;
use serde_json::json;
use tedge_actors::fan_in_message_type;
use tedge_actors::Actor;
use tedge_actors::ChannelError;
use tedge_actors::ClientMessageBox;
use tedge_actors::LoggingSender;
use tedge_actors::MessageReceiver;
use tedge_actors::NoMessage;
use tedge_actors::RuntimeError;
use tedge_actors::Sender;
use tedge_actors::SimpleMessageBox;
use tedge_api::Jsonify;
use tedge_file_system_ext::FsWatchEvent;
use tedge_http_ext::HttpError;
use tedge_http_ext::HttpRequest;
use tedge_http_ext::HttpRequestBuilder;
use tedge_http_ext::HttpResponseExt;
use tedge_http_ext::HttpResult;
use tedge_mqtt_ext::MqttMessage;
use tedge_mqtt_ext::Topic;

use super::error::LogManagementError;
use super::LogManagerConfig;
use super::DEFAULT_PLUGIN_CONFIG_FILE_NAME;
use tedge_api::messages::CommandStatus;
use tedge_api::messages::LogUploadCmdPayload;

fan_in_message_type!(LogInput[MqttMessage, FsWatchEvent] : Debug);
fan_in_message_type!(LogOutput[MqttMessage]: Debug);

pub struct LogManagerActor {
    config: LogManagerConfig,
    plugin_config: LogPluginConfig,
    mqtt_publisher: LoggingSender<MqttMessage>,
    messages: SimpleMessageBox<LogInput, NoMessage>,
    http_proxy: ClientMessageBox<HttpRequest, HttpResult>,
}

#[async_trait]
impl Actor for LogManagerActor {
    fn name(&self) -> &str {
        "LogManager"
    }

    async fn run(&mut self) -> Result<(), RuntimeError> {
        self.reload_supported_log_types().await?;

        while let Some(event) = self.messages.recv().await {
            match event {
                LogInput::MqttMessage(message) => {
                    self.process_mqtt_message(message).await?;
                }
                LogInput::FsWatchEvent(event) => {
                    self.process_file_watch_events(event).await?;
                }
            }
        }
        Ok(())
    }
}

impl LogManagerActor {
    pub fn new(
        config: LogManagerConfig,
        plugin_config: LogPluginConfig,
        mqtt_publisher: LoggingSender<MqttMessage>,
        messages: SimpleMessageBox<LogInput, NoMessage>,
        http_proxy: ClientMessageBox<HttpRequest, HttpResult>,
    ) -> Self {
        Self {
            config,
            plugin_config,
            mqtt_publisher,
            messages,
            http_proxy,
        }
    }

    pub async fn process_mqtt_message(&mut self, message: MqttMessage) -> Result<(), ChannelError> {
        if self.config.logfile_request_topic.accept(&message) {
            match request_from_message(&message) {
                Ok(request) => {
                    if (request.status.eq(&CommandStatus::Executing)
                        || request.status.eq(&CommandStatus::Init))
                        && !self.config.current_operations.contains(&message.topic.name)
                    {
                        info!("Log request received: {request:?}");
                        self.config
                            .current_operations
                            .insert(message.topic.name.clone());
                        self.handle_logfile_request_operation(&message.topic, request)
                            .await?;
                    }
                }
                Err(err) => {
                    error!("Incorrect log request payload: {}", err);
                }
            }
        } else {
            error!(
                "Received unexpected message on topic: {}",
                message.topic.name
            );
        }

        Ok(())
    }

    pub async fn handle_logfile_request_operation(
        &mut self,
        topic: &Topic,
        mut request: LogUploadCmdPayload,
    ) -> Result<(), ChannelError> {
        if !request.status.eq(&CommandStatus::Executing) {
            request.executing();
            self.publish_command_status(topic, &request).await?;
        }
        match self.execute_logfile_request_operation(&request).await {
            Ok(()) => {
                request.successful();
                self.publish_command_status(topic, &request).await?;

                self.config.current_operations.remove(&topic.name);

                info!("Log request processed for log type: {}.", request.log_type);
                Ok(())
            }
            Err(error) => {
                let error_message = format!("Handling of operation failed with {}", error);
                request.failed(&error_message);
                self.publish_command_status(topic, &request).await?;
                self.config.current_operations.remove(&topic.name);

                error!("{}", error_message);
                Ok(())
            }
        }
    }

    /// executes the log file request
    ///
    /// - sends request executing (mqtt)
    /// - uploads log content (http)
    /// - sends request successful (mqtt)
    async fn execute_logfile_request_operation(
        &mut self,
        request: &LogUploadCmdPayload,
    ) -> Result<(), LogManagementError> {
        let log_content = log_manager::new_read_logs(
            &self.plugin_config.files,
            &request.log_type,
            request.date_from,
            request.max_lines.to_owned(),
            &request.search_text,
        )?;

        self.send_log_file_http(log_content, request.tedge_url.clone())
            .await?;

        Ok(())
    }

    async fn send_log_file_http(
        &mut self,
        log_content: String,
        url: String,
    ) -> Result<(), LogManagementError> {
        let req_builder = HttpRequestBuilder::put(&url)
            .header("Content-Type", "text/plain")
            .body(log_content);

        let request = req_builder.build()?;

        let http_result = match self.http_proxy.await_response(request).await? {
            Ok(response) => match response.status() {
                StatusCode::OK | StatusCode::CREATED => Ok(response),
                code => Err(HttpError::HttpStatusError(code)),
            },
            Err(err) => Err(err),
        };

        let _ = http_result.error_for_status()?;
        info!("Logfile uploaded to: {}.", url);
        Ok(())
    }

    async fn process_file_watch_events(&mut self, event: FsWatchEvent) -> Result<(), ChannelError> {
        let path = match event {
            FsWatchEvent::Modified(path) => path,
            FsWatchEvent::FileDeleted(path) => path,
            FsWatchEvent::FileCreated(path) => path,
            FsWatchEvent::DirectoryDeleted(_) => return Ok(()),
            FsWatchEvent::DirectoryCreated(_) => return Ok(()),
        };

        match path.file_name() {
            Some(path) if path.eq(DEFAULT_PLUGIN_CONFIG_FILE_NAME) => {
                self.reload_supported_log_types().await?;
                Ok(())
            }
            Some(_) => Ok(()),
            None => {
                error!(
                    "Path for {} does not exist",
                    DEFAULT_PLUGIN_CONFIG_FILE_NAME
                );
                Ok(())
            }
        }
    }

    async fn reload_supported_log_types(&mut self) -> Result<(), ChannelError> {
        let plugin_config: LogPluginConfig =
            LogPluginConfig::new(self.config.plugin_config_path.as_path());
        self.publish_supported_log_types(&plugin_config).await
    }

    /// updates the log types
    async fn publish_supported_log_types(
        &mut self,
        plugin_config: &LogPluginConfig,
    ) -> Result<(), ChannelError> {
        let mut config_types = plugin_config.get_all_file_types();
        config_types.sort();
        let payload = json!({ "types": config_types }).to_string();
        let msg = MqttMessage::new(&self.config.logtype_reload_topic, payload).with_retain();
        self.mqtt_publisher.send(msg).await
    }

    async fn publish_command_status(
        &mut self,
        topic: &Topic,
        request: &LogUploadCmdPayload,
    ) -> Result<(), ChannelError> {
        match request_into_message(topic, request) {
            Ok(message) => self.mqtt_publisher.send(message).await?,
            Err(err) => error!("Fail to build a message for {:?}: {err}", request),
        }
        Ok(())
    }
}

fn request_from_message(message: &MqttMessage) -> Result<LogUploadCmdPayload, LogManagementError> {
    Ok(LogUploadCmdPayload::from_json(message.payload_str()?)?)
}

fn request_into_message(
    topic: &Topic,
    request: &LogUploadCmdPayload,
) -> Result<MqttMessage, LogManagementError> {
    Ok(MqttMessage::new(topic, request.to_json()?).with_retain())
}
