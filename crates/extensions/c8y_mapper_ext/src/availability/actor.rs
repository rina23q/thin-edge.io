use crate::availability::AvailabilityConfig;
use crate::availability::AvailabilityInput;
use crate::availability::AvailabilityOutput;
use crate::availability::C8yJsonInventoryUpdate;
use crate::availability::C8ySmartRestSetInterval117;
use crate::availability::TimerStart;
use async_trait::async_trait;
use c8y_api::smartrest::topic::C8yTopic;
use serde_json::json;
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;
use tedge_actors::Actor;
use tedge_actors::LoggingSender;
use tedge_actors::MessageReceiver;
use tedge_actors::RuntimeError;
use tedge_actors::Sender;
use tedge_actors::SimpleMessageBox;
use tedge_api::entity_store::EntityExternalId;
use tedge_api::entity_store::EntityRegistrationMessage;
use tedge_api::entity_store::EntityType;
use tedge_api::mqtt_topics::EntityTopicId;
use tedge_api::mqtt_topics::ServiceTopicId;
use tedge_api::HealthStatus;
use tedge_api::Status;
use tedge_timer_ext::SetTimeout;
use tracing::debug;
use tracing::info;
use tracing::warn;

/// The timer payload. Keep it a struct in case if we need more data inside the payload in the future
/// `topic_id` is the EntityTopicId of the target device for availability monitoring
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TimerPayload {
    pub topic_id: EntityTopicId,
}

/// IDs can be retrieved from the registration message's payload
#[derive(Debug)]
struct DeviceIds {
    service_topic_id: ServiceTopicId,
    external_id: EntityExternalId,
}

#[derive(Debug)]
enum RegistrationResult {
    New,
    Update,
    Error(String),
}

pub struct AvailabilityActor {
    config: AvailabilityConfig,
    message_box: SimpleMessageBox<AvailabilityInput, AvailabilityOutput>,
    timer_sender: LoggingSender<TimerStart>,
    device_ids_map: HashMap<EntityTopicId, DeviceIds>,
    service_status_map: HashMap<ServiceTopicId, HealthStatus>,
}

#[async_trait]
impl Actor for AvailabilityActor {
    fn name(&self) -> &str {
        "AvailabilityActor"
    }

    async fn run(mut self) -> Result<(), RuntimeError> {
        if !self.config.enable {
            info!("Device availability monitoring feature is disabled. To enable it, run 'tedge config set c8y.availability.enable true'");
            return Ok(());
        }

        self.init().await?;

        while let Some(input) = self.message_box.recv().await {
            match input {
                AvailabilityInput::EntityRegistrationMessage(message) => {
                    self.process_registration_message(&message).await?;
                }
                AvailabilityInput::SourceHealthStatus((source, health_status)) => {
                    // Insert a "service topic ID" - "health status" pair to the map.
                    self.service_status_map.insert(source, health_status);
                }
                AvailabilityInput::TimerComplete(event) => {
                    self.process_timer_complete(event.event).await?;
                }
            }
        }

        Ok(())
    }
}

impl AvailabilityActor {
    pub fn new(
        config: AvailabilityConfig,
        message_box: SimpleMessageBox<AvailabilityInput, AvailabilityOutput>,
        timer_sender: LoggingSender<TimerStart>,
    ) -> Self {
        Self {
            config,
            message_box,
            timer_sender,
            device_ids_map: HashMap::new(),
            service_status_map: HashMap::new(),
        }
    }

    /// Init function to set up for the main device
    async fn init(&mut self) -> Result<(), RuntimeError> {
        let topic_id = EntityTopicId::default_main_device();

        self.device_ids_map.insert(
            topic_id.clone(),
            DeviceIds {
                service_topic_id: EntityTopicId::default_main_service("tedge-agent")
                    .unwrap()
                    .into(),
                external_id: self.config.main_device_id.clone(),
            },
        );

        self.send_smartrest_set_required_availability_for_main_device()
            .await?;
        self.start_heartbeat_timer_if_interval_is_positive(&topic_id)
            .await?;

        Ok(())
    }

    async fn process_registration_message(
        &mut self,
        message: &EntityRegistrationMessage,
    ) -> Result<(), RuntimeError> {
        let source = &message.topic_id;

        match message.r#type {
            EntityType::MainDevice => match self.update_device_service_pair(message) {
                RegistrationResult::New | RegistrationResult::Update => {
                    self.start_heartbeat_timer_if_interval_is_positive(source)
                        .await?;
                }
                RegistrationResult::Error(reason) => {
                    warn!(reason)
                }
            },
            EntityType::ChildDevice => match self.update_device_service_pair(message) {
                RegistrationResult::New => {
                    self.send_smartrest_set_required_availability_for_child_device(source)
                        .await?;
                    self.start_heartbeat_timer_if_interval_is_positive(source)
                        .await?;
                }
                RegistrationResult::Update => {
                    self.start_heartbeat_timer_if_interval_is_positive(source)
                        .await?;
                }
                RegistrationResult::Error(reason) => warn!(reason),
            },
            EntityType::Service => {}
        }

        Ok(())
    }

    /// Insert a <"device topic ID" - "service topic ID" and "external ID"> pair into the map.
    /// If @health is provided in the registration message, use the value as long as it's valid as a service topic ID.
    /// If @health is not provided, use the "tedge-agent" service topic ID as default.
    /// @id is the only source to know the device's external ID. Hence, @id must be provided in the registration message.
    fn update_device_service_pair(
        &mut self,
        registration_message: &EntityRegistrationMessage,
    ) -> RegistrationResult {
        let source = &registration_message.topic_id;

        let result = match registration_message.other.get("@health") {
            None => {
                Ok(registration_message.topic_id.to_default_service_topic_id("tedge-agent").unwrap())
            }
            Some(raw_value) => {
                match raw_value.as_str() {
                    None => Err(format!("'@health' must hold a string value. Given: {raw_value:?}")),
                    Some(maybe_service_topic_id) => {
                        EntityTopicId::from_str(maybe_service_topic_id)
                            .map(|id| id.into())
                            .map_err(|_| format!("'@health' must be the default service topic schema 'device/DEVICE_NAME/service/SERVICE_NAME'. Given: {maybe_service_topic_id}"))
                    }
                }
            }
        };

        match result {
            Ok(service_topic_id) => {
                match registration_message.external_id.clone() {
                    None => RegistrationResult::Error(format!("'@id' field is missing. Cannot start availability monitoring for the device '{source}'")),
                    Some(external_id) => {
                        match self.device_ids_map
                            .insert(source.clone(), DeviceIds { service_topic_id, external_id }) {
                            None => RegistrationResult::New,
                            Some(_) => RegistrationResult::Update,
                        }
                    }
                }
            }
            Err(err) => RegistrationResult::Error(format!("'@health' contains invalid value in {source}. Details: {err}")),
        }
    }

    /// Set a new timer for heartbeat
    /// Caution: the heartbeat interval from config is defined in MINUTES, not seconds
    async fn start_heartbeat_timer_if_interval_is_positive(
        &mut self,
        source: &EntityTopicId,
    ) -> Result<(), RuntimeError> {
        if self.config.interval > 0 {
            let interval: u64 = self.config.interval.try_into().unwrap();
            self.timer_sender
                .send(SetTimeout::new(
                    Duration::from_secs(interval * 60),
                    TimerPayload {
                        topic_id: source.clone(),
                    },
                ))
                .await?;
        }

        Ok(())
    }

    /// Send SmartREST 117
    /// https://cumulocity.com/docs/smartrest/mqtt-static-templates/#117
    async fn send_smartrest_set_required_availability_for_main_device(
        &mut self,
    ) -> Result<(), RuntimeError> {
        let c8y_117 = C8ySmartRestSetInterval117 {
            c8y_topic: C8yTopic::SmartRestResponse,
            interval: self.config.interval,
        };
        self.message_box.send(c8y_117.into()).await?;

        Ok(())
    }

    /// Send SmartREST 117
    /// https://cumulocity.com/docs/smartrest/mqtt-static-templates/#117
    async fn send_smartrest_set_required_availability_for_child_device(
        &mut self,
        source: &EntityTopicId,
    ) -> Result<(), RuntimeError> {
        if let Some(external_id) = self
            .device_ids_map
            .get(source)
            .map(|ids| ids.external_id.clone())
        {
            let c8y_117 = C8ySmartRestSetInterval117 {
                c8y_topic: C8yTopic::ChildSmartRestResponse(external_id.into()),
                interval: self.config.interval,
            };

            self.message_box.send(c8y_117.into()).await?;
        }

        Ok(())
    }

    async fn process_timer_complete(
        &mut self,
        timer_payload: TimerPayload,
    ) -> Result<(), RuntimeError> {
        let entity_topic_id = timer_payload.topic_id;
        if let Some((service_topic_id, external_id)) = self
            .device_ids_map
            .get(&entity_topic_id)
            .map(|ids| (&ids.service_topic_id, ids.external_id.as_ref()))
        {
            if let Some(health_status) = self.service_status_map.get(service_topic_id) {
                // Send an empty JSON over MQTT message if the target service status is "up"
                if health_status.status == Status::Up {
                    let json_over_mqtt = C8yJsonInventoryUpdate {
                        external_id: external_id.into(),
                        payload: json!({}),
                    };
                    self.message_box.send(json_over_mqtt.into()).await?;
                } else {
                    debug!("Heartbeat message is not sent because the status of the service '{service_topic_id}' is not 'up'");
                }
            }

            // Set a new timer
            self.start_heartbeat_timer_if_interval_is_positive(&entity_topic_id)
                .await?;
        };

        Ok(())
    }
}
