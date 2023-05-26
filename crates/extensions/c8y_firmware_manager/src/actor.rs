use async_trait::async_trait;
use c8y_http_proxy::credentials::JwtRetriever;
use log::error;
use log::info;
use log::warn;
use sha256::digest;
use sha256::try_digest;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs as unix_fs;
use std::path::Path;
use std::path::PathBuf;
use tedge_actors::fan_in_message_type;
use tedge_actors::Actor;
use tedge_actors::ChannelError;
use tedge_actors::DynSender;
use tedge_actors::LoggingReceiver;
use tedge_actors::MessageReceiver;
use tedge_actors::RuntimeError;
use tedge_actors::RuntimeRequest;
use tedge_actors::Sender;
use tedge_actors::WrappedInput;
use tedge_api::topic::get_child_id_from_child_topic;
use tedge_api::Auth;
use tedge_api::OperationStatus;
use tedge_downloader_ext::DownloadRequest;
use tedge_downloader_ext::DownloadResult;
use tedge_mqtt_ext::MqttMessage;
use tedge_mqtt_ext::Topic;
use tedge_timer_ext::SetTimeout;
use tedge_timer_ext::Timeout;
use tedge_utils::file::move_file;
use tedge_utils::file::PermissionEntry;

use crate::config::FirmwareManagerConfig;
use crate::error::DirectoryError;
use crate::error::JwtRetrievalError;
use crate::json::NewFirmwareRequest;
use crate::json::OperationStatusPayload;
use crate::message::FirmwareOperationRequest;
use crate::message::FirmwareOperationResponse;
use crate::operation::CacheAvailability;
use crate::operation::FirmwareOperationEntry;
use crate::operation::OperationKey;
use crate::operation::RequestKind;

pub type OperationSetTimeout = SetTimeout<OperationKey>;
pub type OperationTimeout = Timeout<OperationKey>;

pub type OperationId = String;
pub type IdDownloadResult = (OperationId, DownloadResult);
pub type IdDownloadRequest = (OperationId, DownloadRequest);

fan_in_message_type!(FirmwareInput[MqttMessage, OperationTimeout, IdDownloadResult] : Debug);
fan_in_message_type!(FirmwareOutput[MqttMessage, OperationSetTimeout, IdDownloadRequest] : Debug);

pub struct FirmwareManagerActor {
    config: FirmwareManagerConfig,
    reqs_pending_download: HashMap<String, NewFirmwareRequest>,
    message_box: FirmwareManagerMessageBox,
}

#[async_trait]
impl Actor for FirmwareManagerActor {
    fn name(&self) -> &str {
        "FirmwareManager"
    }

    async fn run(&mut self) -> Result<(), RuntimeError> {
        match self.get_operations_in_progress() {
            Ok(ops) => {
                self.resend_operations_to_child_device(ops).await?;
            }
            Err(err) => {
                error!("Directory error {err:?}")
            }
        }

        info!("Ready to serve firmware requests.");
        while let Some(event) = self.message_box.recv().await {
            match event {
                FirmwareInput::MqttMessage(message) => {
                    self.process_mqtt_message(message).await?;
                }
                FirmwareInput::OperationTimeout(timeout) => {
                    self.process_operation_timeout(timeout).await?;
                }
                FirmwareInput::IdDownloadResult((id, result)) => {
                    self.process_downloaded_firmware(&id, result).await?
                }
            }
        }
        Ok(())
    }
}

impl FirmwareManagerActor {
    pub fn new(config: FirmwareManagerConfig, message_box: FirmwareManagerMessageBox) -> Self {
        Self {
            config,
            reqs_pending_download: HashMap::new(),
            message_box,
        }
    }

    // Based on the topic name, process either a new firmware update operation from the cloud or a response from child device.
    pub async fn process_mqtt_message(&mut self, message: MqttMessage) -> Result<(), ChannelError> {
        if self.config.c8y_request_topics.accept(&message) {
            self.handle_firmware_update_json_request(message).await?;
        } else if self.config.firmware_update_response_topics.accept(&message) {
            self.handle_child_device_firmware_operation_response(message.clone())
                .await?;
        } else {
            error!(
                "Received unexpected message on topic: {}",
                message.topic.name
            );
        }
        Ok(())
    }

    pub async fn handle_firmware_update_json_request(
        &mut self,
        message: MqttMessage,
    ) -> Result<(), ChannelError> {
        match NewFirmwareRequest::try_from(message.clone()) {
            Ok(request) => {
                info!("Handling c8y_Firmware operation: {request:?}");

                if request.device == self.config.tedge_device_id {
                    warn!("c8y-firmware-plugin does not support firmware operation for the main tedge device. \
                        Please define a custom operation handler for the c8y_Firmware operation.");
                    return Ok(());
                }

                self.handle_firmware_download_request(request).await?;
            }
            Err(_) => {
                error!("Incorrect Firmware Request payload: {message:?}");
            }
        }
        Ok(())
    }

    async fn handle_firmware_download_request(
        &mut self,
        request: NewFirmwareRequest,
    ) -> Result<(), ChannelError> {
        let op_id = request.id.clone();

        match self.validate_same_request_in_progress(&op_id) {
            Ok(RequestKind::New) => {
                match self.is_firmware_already_in_cache(request.clone()) {
                    Ok(CacheAvailability::New(path)) => {
                        match self
                            .create_firmware_download_request(request.clone(), path)
                            .await
                        {
                            Ok((id, download_request)) => {
                                // Send firmware download request
                                self.message_box
                                    .download_sender
                                    .send((id.clone(), download_request))
                                    .await?;
                                self.reqs_pending_download.insert(id, request);
                            }
                            Err(JwtRetrievalError::FromChannelError(err)) => return Err(err),
                            Err(JwtRetrievalError::NoJwtToken) => {
                                self.fail_operation_in_cloud(
                                    &op_id,
                                    &JwtRetrievalError::NoJwtToken.to_string(),
                                )
                                .await?;
                            }
                        }
                    }
                    Ok(CacheAvailability::AlreadyInCache(path)) => {
                        info!(
                            "Hit the file cache={}. File download is skipped.",
                            path.display()
                        );
                        match self
                            .handle_firmware_update_request_with_downloaded_file(request, &path)
                            .await
                        {
                            Ok((mqtt_message, set_timeout)) => {
                                self.message_box.mqtt_publisher.send(mqtt_message).await?;
                                self.message_box.timer_sender.send(set_timeout).await?;
                            }
                            Err(err) => {
                                self.fail_operation_in_cloud(&op_id, &err.to_string())
                                    .await?;
                            }
                        }
                    }
                    Err(err) => {
                        self.fail_operation_in_cloud(&op_id, &err.to_string())
                            .await?;
                    }
                }
            }
            Ok(RequestKind::AlreadyAddressed(mqtt_message, set_timeout)) => {
                warn!("Skip the received firmware operation as the same operation is already in progress.");
                self.message_box.mqtt_publisher.send(mqtt_message).await?;
                self.message_box.timer_sender.send(set_timeout).await?;
            }
            Err(err) => {
                self.fail_operation_in_cloud(&op_id, &err.to_string())
                    .await?;
            }
        }

        Ok(())
    }

    fn is_firmware_already_in_cache(
        &mut self,
        request: NewFirmwareRequest,
    ) -> Result<CacheAvailability, DirectoryError> {
        let firmware_url = request.firmware.url.as_str();
        let file_cache_key = digest(firmware_url);
        let cache_file_path = self
            .config
            .validate_and_get_cache_dir_path()?
            .join(&file_cache_key);

        if cache_file_path.is_file() {
            Ok(CacheAvailability::AlreadyInCache(cache_file_path))
        } else {
            Ok(CacheAvailability::New(cache_file_path))
        }
    }

    async fn create_firmware_download_request(
        &mut self,
        request: NewFirmwareRequest,
        cache_file_path: PathBuf,
    ) -> Result<IdDownloadRequest, JwtRetrievalError> {
        let auth = if self
            .config
            .c8y_end_point
            .url_is_in_my_tenant_domain(&request.firmware.url)
        {
            match self.message_box.jwt_retriever.await_response(()).await? {
                Ok(token) => Some(Auth::new_bearer(&token)),
                Err(_) => {
                    return Err(JwtRetrievalError::NoJwtToken);
                }
            }
        } else {
            None
        };

        let download_request = DownloadRequest::new(&request.firmware.url, &cache_file_path, auth);

        Ok((request.id, download_request))
    }

    // This function is called on receiving a DownloadResult from the DownloaderActor or when the firmware file is already available in the cache.
    // If the download is successful, publish a firmware request to child device with it
    // Otherwise, fail the operation in the cloud
    async fn process_downloaded_firmware(
        &mut self,
        operation_id: &str,
        download_result: DownloadResult,
    ) -> Result<(), ChannelError> {
        if let Some(request) = self.reqs_pending_download.remove(operation_id) {
            match download_result {
                Ok(response) => {
                    match self
                        .handle_firmware_update_request_with_downloaded_file(
                            request,
                            &response.file_path,
                        )
                        .await
                    {
                        Ok((mqtt_message, set_timeout)) => {
                            self.message_box.mqtt_publisher.send(mqtt_message).await?;
                            self.message_box.timer_sender.send(set_timeout).await?;
                        }
                        Err(err) => {
                            self.fail_operation_in_cloud(operation_id, &err.to_string())
                                .await?;
                        }
                    }
                }
                Err(err) => {
                    let firmware_url = request.firmware.url;
                    let failure_reason = format!("Download from {firmware_url} failed with {err}");
                    self.fail_operation_in_cloud(operation_id, &failure_reason)
                        .await?;
                }
            }
        } else {
            error!("Unexpected: Download completed for unknown operation: {operation_id}");
        }

        Ok(())
    }

    // Publish a firmware update request to the child device with firmware file path in the cache published via the file-transfer service and start the timer
    async fn handle_firmware_update_request_with_downloaded_file(
        &mut self,
        request: NewFirmwareRequest,
        downloaded_firmware: &Path,
    ) -> Result<(MqttMessage, SetTimeout<OperationKey>), DirectoryError> {
        let op_id = request.id.as_str();
        let child_id = request.device.as_str();
        let firmware_url = request.firmware.url.as_str();
        let file_cache_key = digest(firmware_url);
        let cache_dir_path = self.config.validate_and_get_cache_dir_path()?;
        let cache_file_path = cache_dir_path.join(&file_cache_key);

        // If the downloaded firmware is not already in the cache, move it there
        if !downloaded_firmware.starts_with(&cache_dir_path) {
            move_file(
                &downloaded_firmware,
                &cache_file_path,
                PermissionEntry::default(),
            )
            .await?;
        }

        let symlink_path =
            self.create_file_transfer_symlink(child_id, &file_cache_key, &cache_file_path)?;
        let file_transfer_url = format!(
            "http://{}/tedge/file-transfer/{child_id}/firmware_update/{file_cache_key}",
            &self.config.local_http_host
        );
        let file_sha256 = try_digest(symlink_path.as_path())?;

        let operation_entry = FirmwareOperationEntry {
            operation_id: op_id.to_string(),
            child_id: child_id.to_string(),
            name: request.firmware.name.to_string(),
            version: request.firmware.version.to_string(),
            server_url: firmware_url.to_string(),
            file_transfer_url: file_transfer_url.clone(),
            sha256: file_sha256.to_string(),
            attempt: 1,
        };

        operation_entry.create_status_file(&self.config.firmware_dir)?;

        // This check must be after file creation, otherwise error message cannot read other data.
        if let Some(sha256) = request.firmware.sha256 {
            if sha256 != file_sha256 {
                return Err(DirectoryError::MismatchedSha256);
            }
        }

        let mqtt_message = self.get_firmware_update_request(operation_entry)?;
        let set_timeout =
            SetTimeout::new(self.config.timeout_sec, OperationKey::new(child_id, op_id));

        Ok((mqtt_message, set_timeout))
    }

    // This is the start point function when receiving a firmware response from child device.
    async fn handle_child_device_firmware_operation_response(
        &mut self,
        message: MqttMessage,
    ) -> Result<(), ChannelError> {
        let topic_name = &message.topic.name;

        match get_child_id_from_child_topic(topic_name) {
            Some(child_id) => {
                match FirmwareOperationResponse::try_from(&message) {
                    Ok(response) => {
                        match self.handle_child_device_firmware_update_response(&response) {
                            Ok((mqtt_message, maybe_set_timeout)) => {
                                self.message_box.mqtt_publisher.send(mqtt_message).await?;
                                if let Some(set_timeout) = maybe_set_timeout {
                                    self.message_box.timer_sender.send(set_timeout).await?;
                                }
                            }
                            Err(err) => {
                                self.fail_operation_in_cloud(
                                    response.get_payload().operation_id.as_str(),
                                    &err.to_string(),
                                )
                                .await?;
                            }
                        }
                    }
                    Err(err) => {
                        // Ignore bad responses. Eventually, timeout will fail an operation.
                        error!("Received a firmware update response with invalid payload for child {child_id}. Error: {err}");
                    }
                }
            }
            None => {
                error!("Invalid topic received from child device: {topic_name}")
            }
        }
        Ok(())
    }

    fn handle_child_device_firmware_update_response(
        &mut self,
        response: &FirmwareOperationResponse,
    ) -> Result<(MqttMessage, Option<SetTimeout<OperationKey>>), DirectoryError> {
        let child_device_payload = response.get_payload();
        let child_id = response.get_child_id();
        let operation_id = child_device_payload.operation_id.as_str();
        let received_status = child_device_payload.status;

        info!("Firmware update response received. Details: id={operation_id}, child={child_id}, status={received_status:?}");

        let (mqtt_message, maybe_set_timeout) = match received_status {
            OperationStatus::Successful => {
                let mqtt_message = self.create_operation_successful_message(operation_id)?;
                (mqtt_message, None)
            }
            OperationStatus::Failed => {
                let reason = response.get_reason();
                let mqtt_message = self.create_failed_operation_message(operation_id, &reason)?;
                (mqtt_message, None)
            }
            OperationStatus::Executing => {
                let mqtt_message = self.create_operation_executing_message(operation_id)?;
                let set_timeout = SetTimeout::new(
                    self.config.timeout_sec,
                    OperationKey::new(&child_id, operation_id),
                );
                (mqtt_message, Some(set_timeout))
            }
        };

        Ok((mqtt_message, maybe_set_timeout))
    }

    // Called when timeout occurred.
    async fn process_operation_timeout(
        &mut self,
        timeout: OperationTimeout,
    ) -> Result<(), ChannelError> {
        let child_id = timeout.event.child_id;
        let operation_id = timeout.event.operation_id;

        self.fail_operation_in_cloud(
            &operation_id,
            &format!("Child device {child_id} did not respond within the timeout interval of {}sec. Operation ID={operation_id}", self.config.timeout_sec.as_secs()),
        ).await
    }

    fn validate_same_request_in_progress(
        &mut self,
        op_id: &str,
    ) -> Result<RequestKind, DirectoryError> {
        let firmware_dir_path = self.config.validate_and_get_firmware_dir_path()?;
        let entry_file_path = firmware_dir_path.join(op_id);

        match FirmwareOperationEntry::read_from_file(&entry_file_path.as_path()) {
            Ok(old_entry) => {
                info!("The same operation as the received c8y_Firmware operation is already in progress.");

                let new_operation_entry = old_entry.increment_attempt();
                new_operation_entry.overwrite_file(&firmware_dir_path)?;

                let set_timeout = SetTimeout::new(
                    self.config.timeout_sec,
                    OperationKey::new(
                        &new_operation_entry.child_id,
                        &new_operation_entry.operation_id,
                    ),
                );
                let mqtt_message = self.get_firmware_update_request(new_operation_entry)?;

                Ok(RequestKind::AlreadyAddressed(mqtt_message, set_timeout))
            }
            Err(_) => Ok(RequestKind::New),
        }
    }

    async fn fail_operation_in_cloud(
        &mut self,
        operation_id: &str,
        failure_reason: &str,
    ) -> Result<(), ChannelError> {
        error!("{failure_reason}");

        match self.create_failed_operation_message(operation_id, failure_reason) {
            Ok(failed_message) => {
                self.message_box.mqtt_publisher.send(failed_message).await?;
            }
            Err(err) => {
                error!("Error occurred while working on operation entry {err:?}")
            }
        }
        Ok(())
    }

    fn create_failed_operation_message(
        &mut self,
        operation_id: &str,
        failure_reason: &str,
    ) -> Result<MqttMessage, DirectoryError> {
        let file_path = self.config.firmware_dir.join(operation_id);
        let entry = FirmwareOperationEntry::read_from_file(&file_path)?;

        let topic = Topic::new_unchecked(&format!(
            "tedge/{}/commands/firmware_update/done/failed",
            &entry.child_id
        ));

        let payload = OperationStatusPayload::new(
            operation_id,
            OperationStatus::Failed,
            &entry.child_id,
            &entry.name,
            &entry.server_url,
            &entry.version,
            &entry.sha256,
        )
        .with_reason(failure_reason);

        let mqtt_message = MqttMessage::new(&topic, payload.to_string());

        self.remove_status_file(operation_id)?;

        Ok(mqtt_message)
    }

    fn create_operation_executing_message(
        &mut self,
        operation_id: &str,
    ) -> Result<MqttMessage, DirectoryError> {
        let file_path = self.config.firmware_dir.join(operation_id);
        let entry = FirmwareOperationEntry::read_from_file(&file_path)?;

        let topic = Topic::new_unchecked(&format!(
            "tedge/{}/commands/firmware_update/executing",
            entry.child_id
        ));
        let payload = OperationStatusPayload::new(
            &entry.operation_id,
            OperationStatus::Executing,
            &entry.child_id,
            &entry.name,
            &entry.server_url,
            &entry.version,
            &entry.sha256,
        );
        let mqtt_message = MqttMessage::new(&topic, payload.to_string());

        Ok(mqtt_message)
    }

    fn create_operation_successful_message(
        &mut self,
        operation_id: &str,
    ) -> Result<MqttMessage, DirectoryError> {
        let file_path = self.config.firmware_dir.join(operation_id);
        let entry = FirmwareOperationEntry::read_from_file(&file_path)?;

        let topic = Topic::new_unchecked(&format!(
            "tedge/{}/commands/firmware_update/done/successful",
            &entry.child_id
        ));
        let payload = OperationStatusPayload::new(
            &entry.operation_id,
            OperationStatus::Successful,
            &entry.child_id,
            &entry.name,
            &entry.server_url,
            &entry.version,
            &entry.sha256,
        );
        let mqtt_message = MqttMessage::new(&topic, payload.to_string());

        self.remove_status_file(operation_id)?;

        Ok(mqtt_message)
    }

    async fn resend_operations_to_child_device(
        &mut self,
        ops: Vec<(MqttMessage, SetTimeout<OperationKey>)>,
    ) -> Result<(), ChannelError> {
        for (mqtt_message, set_timeout) in ops {
            self.message_box.mqtt_publisher.send(mqtt_message).await?;
            self.message_box.timer_sender.send(set_timeout).await?;
        }
        Ok(())
    }

    fn get_operations_in_progress(
        &mut self,
    ) -> Result<Vec<(MqttMessage, SetTimeout<OperationKey>)>, DirectoryError> {
        let firmware_dir_path = self.config.firmware_dir.clone();
        if !firmware_dir_path.is_dir() {
            // Do nothing if the persistent store directory does not exist yet.
            return Ok(vec![]);
        }

        let mut ops_in_progress = Vec::new();

        for entry in fs::read_dir(&firmware_dir_path)? {
            let file_path = entry?.path();
            if file_path.is_file() {
                let operation_entry =
                    FirmwareOperationEntry::read_from_file(&file_path)?.increment_attempt();
                let operation_key =
                    OperationKey::new(&operation_entry.child_id, &operation_entry.operation_id);

                operation_entry.overwrite_file(&firmware_dir_path)?;

                let mqtt_message = self.get_firmware_update_request(operation_entry)?;
                let set_timeout = SetTimeout::new(self.config.timeout_sec, operation_key);

                ops_in_progress.push((mqtt_message, set_timeout));
            }
        }
        Ok(ops_in_progress)
    }

    fn remove_status_file(&mut self, operation_id: &str) -> Result<(), DirectoryError> {
        let status_file_path = self
            .config
            .validate_and_get_firmware_dir_path()?
            .join(operation_id);
        if status_file_path.exists() {
            fs::remove_file(status_file_path)?;
        }
        Ok(())
    }

    fn get_firmware_update_request(
        &mut self,
        operation_entry: FirmwareOperationEntry,
    ) -> Result<MqttMessage, serde_json::Error> {
        let mqtt_message: MqttMessage =
            FirmwareOperationRequest::from(operation_entry.clone()).try_into()?;
        Ok(mqtt_message)
    }

    // The symlink path should be <tedge-data-dir>/file-transfer/<child-id>/firmware_update/<file_cache_key>
    fn create_file_transfer_symlink(
        &self,
        child_id: &str,
        file_cache_key: &str,
        original_file_path: &Path,
    ) -> Result<PathBuf, DirectoryError> {
        let file_transfer_dir_path = self.config.validate_and_get_file_transfer_dir_path()?;

        let symlink_dir_path = file_transfer_dir_path
            .join(child_id)
            .join("firmware_update");
        let symlink_path = symlink_dir_path.join(file_cache_key);

        if !symlink_path.is_symlink() {
            fs::create_dir_all(symlink_dir_path)?;
            unix_fs::symlink(original_file_path, &symlink_path)?;
        }
        Ok(symlink_path)
    }
}

pub struct FirmwareManagerMessageBox {
    input_receiver: LoggingReceiver<FirmwareInput>,
    mqtt_publisher: DynSender<MqttMessage>,
    jwt_retriever: JwtRetriever,
    timer_sender: DynSender<SetTimeout<OperationKey>>,
    download_sender: DynSender<IdDownloadRequest>,
}

impl FirmwareManagerMessageBox {
    pub fn new(
        input_receiver: LoggingReceiver<FirmwareInput>,
        mqtt_publisher: DynSender<MqttMessage>,
        jwt_retriever: JwtRetriever,
        timer_sender: DynSender<SetTimeout<OperationKey>>,
        download_sender: DynSender<IdDownloadRequest>,
    ) -> Self {
        Self {
            input_receiver,
            mqtt_publisher,
            jwt_retriever,
            timer_sender,
            download_sender,
        }
    }
}

#[async_trait]
impl MessageReceiver<FirmwareInput> for FirmwareManagerMessageBox {
    async fn try_recv(&mut self) -> Result<Option<FirmwareInput>, RuntimeRequest> {
        self.input_receiver.try_recv().await
    }

    async fn recv_message(&mut self) -> Option<WrappedInput<FirmwareInput>> {
        self.input_receiver.recv_message().await
    }

    async fn recv(&mut self) -> Option<FirmwareInput> {
        self.input_receiver.recv().await
    }

    async fn recv_signal(&mut self) -> Option<RuntimeRequest> {
        self.input_receiver.recv_signal().await
    }
}
