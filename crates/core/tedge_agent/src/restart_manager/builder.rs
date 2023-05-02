use crate::restart_manager::actor::RestartManagerActor;
use crate::restart_manager::actor::RestartManagerConfig;
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

pub struct RestartManagerBuilder {
    config: RestartManagerConfig,
    input_receiver: LoggingReceiver<RestartOperationRequest>,
    converter_sender: DynSender<RestartOperationResponse>,
    signal_sender: mpsc::Sender<RuntimeRequest>,
}

impl RestartManagerBuilder {
    pub fn new(
        config: RestartManagerConfig,
        converter_actor: &mut impl ServiceProvider<
            RestartOperationResponse,
            RestartOperationRequest,
            NoConfig,
        >,
    ) -> Self {
        let (input_sender, input_receiver) = mpsc::channel(10);
        let (signal_sender, signal_receiver) = mpsc::channel(10);
        let input_receiver =
            LoggingReceiver::new("Restart-Manager".into(), input_receiver, signal_receiver);

        let converter_sender =
            converter_actor.connect_consumer(NoConfig, input_sender.clone().into());

        Self {
            config,
            input_receiver,
            converter_sender,
            // state_message_box,
            signal_sender,
        }
    }
}

impl RuntimeRequestSink for RestartManagerBuilder {
    fn get_signal_sender(&self) -> DynSender<RuntimeRequest> {
        Box::new(self.signal_sender.clone())
    }
}

impl Builder<RestartManagerActor> for RestartManagerBuilder {
    type Error = LinkError;

    fn try_build(self) -> Result<RestartManagerActor, Self::Error> {
        Ok(self.build())
    }

    fn build(self) -> RestartManagerActor {
        RestartManagerActor::new(self.config, self.input_receiver, self.converter_sender)
    }
}
