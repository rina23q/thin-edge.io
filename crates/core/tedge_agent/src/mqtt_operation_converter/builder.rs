use crate::mqtt_operation_converter::actor::AgentInput;
use crate::mqtt_operation_converter::actor::MqttOperationConverterActor;
use mqtt_channel::TopicFilter;
use tedge_actors::futures::channel::mpsc;
use tedge_actors::Builder;
use tedge_actors::DynSender;
use tedge_actors::LinkError;
use tedge_actors::LoggingReceiver;
use tedge_actors::NoConfig;
use tedge_actors::RuntimeRequest;
use tedge_actors::RuntimeRequestSink;
use tedge_actors::ServiceProvider;
use tedge_api::RestartOperationRequest;
use tedge_api::RestartOperationResponse;
use tedge_api::SoftwareListRequest;
use tedge_api::SoftwareListResponse;
use tedge_api::SoftwareUpdateRequest;
use tedge_api::SoftwareUpdateResponse;
use tedge_mqtt_ext::MqttMessage;

pub struct MqttOperationConverterBuilder {
    input_receiver: LoggingReceiver<AgentInput>,
    software_list_sender: DynSender<SoftwareListRequest>,
    software_update_sender: DynSender<SoftwareUpdateRequest>,
    restart_sender: DynSender<RestartOperationRequest>,
    mqtt_publisher: DynSender<MqttMessage>,
    signal_sender: mpsc::Sender<RuntimeRequest>,
}

impl MqttOperationConverterBuilder {
    pub fn new(
        software_list_actor: &mut impl ServiceProvider<
            SoftwareListRequest,
            SoftwareListResponse,
            NoConfig,
        >,
        software_update_actor: &mut impl ServiceProvider<
            SoftwareUpdateRequest,
            SoftwareUpdateResponse,
            NoConfig,
        >,
        restart_actor: &mut impl ServiceProvider<
            RestartOperationRequest,
            RestartOperationResponse,
            NoConfig,
        >,
        mqtt_actor: &mut impl ServiceProvider<MqttMessage, MqttMessage, TopicFilter>,
    ) -> Self {
        let (input_sender, input_receiver) = mpsc::channel(10);
        let (signal_sender, signal_receiver) = mpsc::channel(10);

        let input_receiver = LoggingReceiver::new(
            "Mqtt-Request-Converter".into(),
            input_receiver,
            signal_receiver,
        );
        let software_list_sender =
            software_list_actor.connect_consumer(NoConfig, input_sender.clone().into());
        let software_update_sender =
            software_update_actor.connect_consumer(NoConfig, input_sender.clone().into());
        let restart_sender = restart_actor.connect_consumer(NoConfig, input_sender.clone().into());
        let mqtt_publisher =
            mqtt_actor.connect_consumer(Self::subscriptions(), input_sender.clone().into());

        Self {
            input_receiver,
            software_list_sender,
            software_update_sender,
            restart_sender,
            mqtt_publisher,
            signal_sender,
        }
    }

    pub fn subscriptions() -> TopicFilter {
        vec![
            "tedge/commands/req/software/list",
            "tedge/commands/req/software/update",
            "tedge/commands/req/control/restart",
        ]
        .try_into()
        .expect("Infallible")
    }
}

impl RuntimeRequestSink for MqttOperationConverterBuilder {
    fn get_signal_sender(&self) -> DynSender<RuntimeRequest> {
        Box::new(self.signal_sender.clone())
    }
}

impl Builder<MqttOperationConverterActor> for MqttOperationConverterBuilder {
    type Error = LinkError;

    fn try_build(self) -> Result<MqttOperationConverterActor, Self::Error> {
        let peers = self.mqtt_publisher;

        Ok(MqttOperationConverterActor::new(
            self.input_receiver,
            self.software_list_sender,
            self.software_update_sender,
            self.restart_sender,
            peers,
        ))
    }
}