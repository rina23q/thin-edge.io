use async_trait::async_trait;
use c8y_api::smartrest::message::collect_smartrest_messages;
use c8y_api::smartrest::message::get_smartrest_template_id;
use c8y_api::smartrest::smartrest_deserializer::SmartRestFirmwareRequest;
use c8y_api::smartrest::smartrest_deserializer::SmartRestRequestGeneric;
use c8y_api::smartrest::smartrest_serializer::SmartRest;
use c8y_api::smartrest::smartrest_serializer::TryIntoOperationStatusMessage;
use c8y_api::smartrest::topic::C8yTopic;
use c8y_http_proxy::handle::C8YHttpProxy;
use mqtt_channel::Topic;
use mqtt_channel::TopicFilter;
use nanoid::nanoid;
use sha256::digest;
use sha256::try_digest;
use std::fs;
use std::os::unix::fs as unix_fs;
use std::path::Path;
use std::path::PathBuf;
use tedge_actors::fan_in_message_type;
use tedge_actors::Actor;
use tedge_actors::ChannelError;
use tedge_actors::CombinedReceiver;
use tedge_actors::DynSender;
use tedge_actors::MessageBox;
use tedge_actors::ReceiveMessages;
use tedge_actors::RuntimeError;
use tedge_actors::RuntimeRequest;
use tedge_actors::WrappedInput;
use tedge_api::health::health_check_topics;
use tedge_api::health::health_status_up_message;
use tedge_api::health::send_health_status;
use tedge_mqtt_ext::MqttMessage;
use tedge_timer_ext::SetTimeout;
use tedge_timer_ext::Timeout;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::config::FirmwareManagerConfig;
use crate::error::FirmwareManagementError;
use crate::error::FirmwareManagementError::DirectoryNotFound;
use crate::message::DownloadFirmwareStatusMessage;
use crate::message::FirmwareOperationRequest;
use crate::operation::ActiveOperationState;
use crate::operation::FirmwareOperationEntry;

#[derive(Clone, Debug)]
pub struct TimerKey {
    pub child_id: String,
    pub operation_id: String,
}
pub type OperationTimer = SetTimeout<TimerKey>;
pub type OperationTimeout = Timeout<TimerKey>;

fan_in_message_type!(FirmwareInput[MqttMessage, OperationTimeout] : Debug);
fan_in_message_type!(FirmwareOutput[MqttMessage, OperationTimer] : Debug);

const PLUGIN_SERVICE_NAME: &str = "c8y-firmware-plugin";

pub struct FirmwareManagerActor {
    config: FirmwareManagerConfig,
    // TODO: Ask Albin. What needs here? Hashmap for pending list for download, or active child ops? Both?
}

#[async_trait]
impl Actor for FirmwareManagerActor {
    type MessageBox = FirmwareManagerMessageBox;

    fn name(&self) -> &str {
        "FirmwareManager"
    }

    async fn run(mut self, mut message_box: Self::MessageBox) -> Result<(), RuntimeError> {
        self.resend_operations_to_child_device(&mut message_box)
            .await?;
        // TODO: Do we need to send 500 from each actor?
        self.get_pending_operations_from_cloud(&mut message_box)
            .await?;
        self.send_health_status_message(&mut message_box).await?;

        info!("Ready to serve the firmware request.");

        while let Some(event) = message_box.recv().await {
            match event {
                FirmwareInput::MqttMessage(message) => {
                    self.process_mqtt_message(message, &mut message_box).await?;
                }
                FirmwareInput::OperationTimeout(timeout) => {
                    self.process_operation_timeout(timeout, &mut message_box)
                        .await?;
                } // TODO: Add downloader
            }
        }
        Ok(())
    }
}

impl FirmwareManagerActor {
    pub fn new(config: FirmwareManagerConfig) -> Self {
        Self { config }
    }

    pub async fn process_mqtt_message(
        &mut self,
        message: MqttMessage,
        message_box: &mut FirmwareManagerMessageBox,
    ) -> Result<(), FirmwareManagementError> {
        if self.config.health_check_topics.accept(&message) {
            self.send_health_status_message(message_box).await?;
            return Ok(());
        } else if self.config.firmware_update_response_topics.accept(&message) {
            self.handle_child_device_firmware_operation_response(message.clone(), message_box)
                .await?;
        } else if self.config.c8y_request_topics.accept(&message) {
            self.handle_firmware_update_smartrest_request(message, message_box)
                .await?;
        } else {
            error!(
                "Received unexpected message on topic: {}",
                message.topic.name
            );
        }
        Ok(())
    }

    pub async fn handle_firmware_update_smartrest_request(
        &mut self,
        message: MqttMessage,
        message_box: &mut FirmwareManagerMessageBox,
    ) -> Result<(), FirmwareManagementError> {
        for smartrest_message in collect_smartrest_messages(message.payload_str()?) {
            let result = match get_smartrest_template_id(smartrest_message.as_str()).as_str() {
                "515" => {
                    match SmartRestFirmwareRequest::from_smartrest(smartrest_message.as_str()) {
                        Ok(firmware_request) => {
                            self.handle_firmware_download_request(firmware_request, message_box)
                                .await
                        }
                        Err(_) => {
                            error!("Incorrect c8y_Firmware SmartREST payload: {smartrest_message}");
                            Ok(())
                        }
                    }
                }
                _ => {
                    // Ignore operation messages not meant for this plugin
                    Ok(())
                }
            };
            if let Err(err) = result {
                error!("Handling of operation: '{smartrest_message}' failed with {err}");
            }
        }
        Ok(())
    }

    async fn handle_firmware_download_request(
        &mut self,
        smartrest_request: SmartRestFirmwareRequest,
        message_box: &mut FirmwareManagerMessageBox,
    ) -> Result<(), FirmwareManagementError> {
        info!(
            "Handling c8y_Firmware operation: device={}, name={}, version={}, url={}",
            smartrest_request.device,
            smartrest_request.name,
            smartrest_request.version,
            smartrest_request.url,
        );

        if smartrest_request.device == self.config.tedge_device_id {
            warn!("c8y-firmware-plugin does not support firmware operation for the main tedge device. \
            Please define a custom operation handler for the c8y_Firmware operation.");
            return Ok(());
        }

        let child_id = smartrest_request.device.as_str();

        if let Err(err) = self
            .validate_same_request_in_progress(smartrest_request.clone())
            .await
        {
            return match err {
                FirmwareManagementError::RequestAlreadyAddressed => {
                    warn!("Skip the received c8y_Firmware operation as the same operation is already in progress.");
                    Ok(())
                }
                _ => {
                    self.fail_operation_in_cloud(&child_id, None, &err.to_string(), message_box)
                        .await?;
                    Err(err)
                }
            };
        }

        let op_id = nanoid!();
        if let Err(err) = self
            .handle_firmware_download_request_child_device(
                smartrest_request.clone(),
                op_id.clone(),
                message_box,
            )
            .await
        {
            self.fail_operation_in_cloud(&child_id, Some(&op_id), &err.to_string(), message_box)
                .await?;
        }

        Ok(())
    }

    async fn handle_firmware_download_request_child_device(
        &mut self,
        smartrest_request: SmartRestFirmwareRequest,
        operation_id: String,
        message_box: &mut FirmwareManagerMessageBox,
    ) -> Result<(), FirmwareManagementError> {
        let firmware_url = smartrest_request.url.as_str();
        let file_cache_key = digest(firmware_url);
        let cache_file_path = self.config.cache_dir.join(&file_cache_key);

        if cache_file_path.is_file() {
            info!(
                "Hit the file cache={}. File download is skipped.",
                cache_file_path.display()
            );
            self.handle_firmware_update_request_with_downloaded_file(
                smartrest_request,
                operation_id,
                &cache_file_path,
                message_box,
            )
            .await?;
        } else {
            unimplemented!();
            // let download_req = DownloadRequest::new(&operation_id, firmware_url, &file_cache_key);

            info!(
                "Awaiting firmware download for op_id: {} from url: {}",
                operation_id, firmware_url
            );
            // Send a request to the DownloadManager to download the file asynchronously
            // self.download_req_sndr.send(download_req).await?;
            // self.reqs_pending_download
            //     .insert(operation_id, smartrest_request);
        }
        Ok(())
    }

    async fn handle_firmware_update_request_with_downloaded_file(
        &mut self,
        smartrest_request: SmartRestFirmwareRequest,
        operation_id: String,
        downloaded_firmware: &Path,
        message_box: &mut FirmwareManagerMessageBox,
    ) -> Result<(), FirmwareManagementError> {
        let child_id = smartrest_request.device.as_str();
        let firmware_url = smartrest_request.url.as_str();
        let file_cache_key = digest(firmware_url);
        let cache_file_path = self.config.cache_dir.join(&file_cache_key);

        // If the downloaded firmware is not already in the cache, move it there
        if !downloaded_firmware.starts_with(&self.config.cache_dir) {
            move_file(downloaded_firmware, &cache_file_path)?;
        }

        // <tedge-persistent-root>/file-transfer/<child-id>/firmware_update/<file_cache_key>
        let symlink_path =
            self.create_file_transfer_symlink(child_id, &file_cache_key, &cache_file_path)?;
        let file_transfer_url = format!(
            "http://{}/tedge/file-transfer/{child_id}/firmware_update/{file_cache_key}",
            &self.config.local_http_host
        );
        let file_sha256 = try_digest(symlink_path.as_path())?;

        let operation_entry = FirmwareOperationEntry {
            operation_id: operation_id.clone(),
            child_id: child_id.to_string(),
            name: smartrest_request.name.to_string(),
            version: smartrest_request.version.to_string(),
            server_url: firmware_url.to_string(),
            file_transfer_url: file_transfer_url.clone(),
            sha256: file_sha256.to_string(),
            attempt: 1,
        };

        operation_entry.create_status_file(&self.config.firmware_dir)?;

        self.send_firmware_update_request(operation_entry, message_box)
            .await?;

        // TODO: Ask Albin about the tinmer.
        // self.operation_timer.start_timer(
        //     (child_id.to_string(), operation_id),
        //     ActiveOperationState::Pending,
        //     self.timeout_sec,
        // );

        Ok(())
    }

    async fn handle_child_device_firmware_operation_response(
        &mut self,
        message: MqttMessage,
        message_box: &mut FirmwareManagerMessageBox,
    ) -> Result<(), FirmwareManagementError> {
        unimplemented!()
    }

    async fn process_operation_timeout(
        &mut self,
        timeout: OperationTimeout,
        message_box: &mut FirmwareManagerMessageBox,
    ) -> Result<(), FirmwareManagementError> {
        let child_id = timeout.event.child_id;
        let operation_key = TimerKey {
            child_id: child_id.clone(),
            operation_id: timeout.event.operation_id,
        };

        // TODO! Mistery of Timer. Ask Albin.
        unimplemented!()
        // if let Some(operation_state) = self.active_child_ops.remove(&operation_key) {
        //     ConfigManagerActor::fail_config_operation_in_c8y(
        //         ConfigOperation::Update,
        //         Some(child_id.clone()),
        //         operation_state,
        //         format!("Timeout due to lack of response from child device: {child_id} for config type: {config_type}"),
        //         message_box,
        //     ).await
        // } else {
        //     // Ignore the timeout as the operation has already completed.
        //     Ok(())
        // }
    }

    // This function can be removed once we start using operation ID from c8y.
    async fn validate_same_request_in_progress(
        &mut self,
        smartrest_request: SmartRestFirmwareRequest,
    ) -> Result<(), FirmwareManagementError> {
        let firmware_dir_path = self.config.firmware_dir.clone();

        validate_dir_exists(&firmware_dir_path)?;

        for entry in fs::read_dir(firmware_dir_path.clone())? {
            match entry {
                Ok(file_path) => match FirmwareOperationEntry::read_from_file(&file_path.path()) {
                    Ok(recorded_entry) => {
                        if recorded_entry.child_id == smartrest_request.device
                            && recorded_entry.name == smartrest_request.name
                            && recorded_entry.version == smartrest_request.version
                            && recorded_entry.server_url == smartrest_request.url
                        {
                            return Err(FirmwareManagementError::RequestAlreadyAddressed);
                        }
                    }
                    Err(err) => {
                        warn!("Error: {err} while reading the contents of persistent store directory {}",
                            firmware_dir_path.display());
                        continue;
                    }
                },
                Err(err) => {
                    warn!(
                        "Error: {err} while reading the contents of persistent store directory {}",
                        firmware_dir_path.display()
                    );
                    continue;
                }
            }
        }
        Ok(())
    }

    async fn fail_operation_in_cloud(
        &mut self,
        child_id: impl ToString,
        op_id: Option<&str>,
        failure_reason: &str,
        message_box: &mut FirmwareManagerMessageBox,
    ) -> Result<(), FirmwareManagementError> {
        error!(failure_reason);
        let op_state = if let Some(operation_id) = op_id {
            let status_file_path = self.config.firmware_dir.join(operation_id);
            if status_file_path.exists() {
                fs::remove_file(status_file_path)?;
            }
            // FIXME: Operation timer with actor
            // self.operation_timer
            //     .stop_timer((child_id.to_string(), operation_id.to_string()))
            //     .unwrap_or(ActiveOperationState::Pending)
            ActiveOperationState::Pending
        } else {
            ActiveOperationState::Pending
        };

        let c8y_child_topic = Topic::new_unchecked(
            &C8yTopic::ChildSmartRestResponse(child_id.to_string()).to_string(),
        );

        let executing_msg = MqttMessage::new(
            &c8y_child_topic,
            DownloadFirmwareStatusMessage::status_executing()?,
        );
        let failed_msg = MqttMessage::new(
            &c8y_child_topic,
            DownloadFirmwareStatusMessage::status_failed(failure_reason.to_string())?,
        );

        if op_state == ActiveOperationState::Pending {
            message_box.send(executing_msg.into()).await?;
        }

        message_box.send(failed_msg.into()).await?;

        Ok(())
    }

    async fn resend_operations_to_child_device(
        &mut self,
        message_box: &mut FirmwareManagerMessageBox,
    ) -> Result<(), FirmwareManagementError> {
        let firmware_dir_path = self.config.firmware_dir.clone();
        if !firmware_dir_path.is_dir() {
            // Do nothing if the persistent store directory does not exist yet.
            return Ok(());
        }

        for entry in fs::read_dir(&firmware_dir_path)? {
            let file_path = entry?.path();
            if file_path.is_file() {
                let operation_entry =
                    FirmwareOperationEntry::read_from_file(&file_path)?.increment_attempt();
                operation_entry.overwrite_file(&firmware_dir_path)?;

                let mqtt_message: MqttMessage =
                    FirmwareOperationRequest::from(operation_entry.clone()).try_into()?;
                message_box.send(mqtt_message.into()).await?;
                info!(
                    "Firmware update request is resent. operation_id={}, child={}",
                    operation_entry.operation_id, operation_entry.child_id
                );

                // TODO: Albin. Timer implementation
                // self.operation_timer.start_timer(
                //     (operation_entry.child_id, operation_entry.operation_id),
                //     ActiveOperationState::Pending,
                //     self.timeout_sec,
                // );
            }
        }
        Ok(())
    }

    async fn get_pending_operations_from_cloud(
        &mut self,
        message_box: &mut FirmwareManagerMessageBox,
    ) -> Result<(), FirmwareManagementError> {
        let message = MqttMessage::new(&C8yTopic::SmartRestResponse.to_topic()?, "500");
        message_box.send(message.into()).await?;
        Ok(())
    }

    async fn send_health_status_message(
        &mut self,
        message_box: &mut FirmwareManagerMessageBox,
    ) -> Result<(), FirmwareManagementError> {
        let message = health_status_up_message("c8y-firmware-plugin"); // Question: isn't it just one process?
        message_box.send(message.into()).await?;
        Ok(())
    }

    fn get_cache_file_path(
        &self,
        file_cache_key: &str,
    ) -> Result<PathBuf, FirmwareManagementError> {
        validate_dir_exists(&self.config.cache_dir)?;
        Ok(self.config.cache_dir.join(file_cache_key))
    }

    fn create_file_transfer_symlink(
        &self,
        child_id: &str,
        file_cache_key: &str,
        original_path: &Path,
    ) -> Result<PathBuf, FirmwareManagementError> {
        let file_transfer_dir_path = self.config.file_transfer_dir.as_path();
        validate_dir_exists(file_transfer_dir_path)?;

        let symlink_dir_path = file_transfer_dir_path
            .join(child_id)
            .join("firmware_update");
        let symlink_path = symlink_dir_path.join(file_cache_key);

        if !symlink_path.is_symlink() {
            fs::create_dir_all(symlink_dir_path)?;
            unix_fs::symlink(original_path, &symlink_path)?;
        }
        Ok(symlink_path)
    }

    async fn send_firmware_update_request(
        &mut self,
        operation_entry: FirmwareOperationEntry,
        message_box: &mut FirmwareManagerMessageBox,
    ) -> Result<(), FirmwareManagementError> {
        let mqtt_message: MqttMessage =
            FirmwareOperationRequest::from(operation_entry.clone()).try_into()?;
        message_box.send(mqtt_message.into()).await?;
        info!(
            "Firmware update request is sent. operation_id={}, child={}",
            operation_entry.operation_id, operation_entry.child_id
        );
        Ok(())
    }
}

pub struct FirmwareManagerMessageBox {
    input_receiver: CombinedReceiver<FirmwareInput>,
    mqtt_publisher: DynSender<MqttMessage>,
    c8y_http_proxy: C8YHttpProxy,
    timer_sender: DynSender<SetTimeout<TimerKey>>,
}

impl FirmwareManagerMessageBox {
    pub fn new(
        input_receiver: CombinedReceiver<FirmwareInput>,
        mqtt_publisher: DynSender<MqttMessage>,
        c8y_http_proxy: C8YHttpProxy,
        timer_sender: DynSender<SetTimeout<TimerKey>>,
    ) -> Self {
        Self {
            input_receiver,
            mqtt_publisher,
            c8y_http_proxy,
            timer_sender,
        }
    }

    async fn send(&mut self, message: FirmwareOutput) -> Result<(), ChannelError> {
        match message {
            FirmwareOutput::MqttMessage(message) => self.mqtt_publisher.send(message).await,
            FirmwareOutput::OperationTimer(message) => self.timer_sender.send(message).await,
        }
    }
}

#[async_trait]
impl ReceiveMessages<FirmwareInput> for FirmwareManagerMessageBox {
    async fn try_recv(&mut self) -> Result<Option<FirmwareInput>, RuntimeRequest> {
        self.input_receiver.try_recv().await
    }

    async fn recv_message(&mut self) -> Option<WrappedInput<FirmwareInput>> {
        self.input_receiver.recv_message().await
    }

    async fn recv(&mut self) -> Option<FirmwareInput> {
        self.input_receiver.recv().await.map(|message| {
            self.log_input(&message);
            message
        })
    }
}

impl MessageBox for FirmwareManagerMessageBox {
    type Input = FirmwareInput;
    type Output = MqttMessage;

    fn turn_logging_on(&mut self, _on: bool) {
        todo!()
    }

    fn name(&self) -> &str {
        "C8Y-Firmware-Manager"
    }

    fn logging_is_on(&self) -> bool {
        // FIXME this mailbox recv and send method are not used making logging ineffective.
        false
    }
}

fn validate_dir_exists(dir_path: &Path) -> Result<(), FirmwareManagementError> {
    if dir_path.exists() {
        Ok(())
    } else {
        Err(DirectoryNotFound {
            path: dir_path.to_path_buf(),
        })
    }
}

// TODO! Remove it and use tedge_utils/move_file instead.
fn move_file(src: &Path, dest: &Path) -> Result<(), FirmwareManagementError> {
    fs::copy(src, dest).map_err(|_| FirmwareManagementError::FileCopyFailed {
        src: src.to_path_buf(),
        dest: dest.to_path_buf(),
    })?;

    Ok(())
}
