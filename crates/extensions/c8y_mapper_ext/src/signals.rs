use crate::converter::CumulocityConverter;
use crate::error::ConversionError;
use tedge_api::mqtt_topics::SignalType;
use tedge_mqtt_ext::MqttMessage;

impl CumulocityConverter {
    pub fn process_signal_message(
        &mut self,
        signal_type: &SignalType,
    ) -> Result<Vec<MqttMessage>, ConversionError> {
        let mut messages = Vec::new();

        match signal_type {
            SignalType::Operations => {
                // Doing the following actions upon `cmd/operations/check` isn't enough?
                let main_message = self.load_and_create_supported_operations_messages(
                    &self.config.device_id.clone(),
                )?;
                let mut child_messages = self.send_child_supported_operation_messages()?;
                messages.append(&mut vec![main_message]);
                messages.append(&mut child_messages);
            }
            SignalType::ConfigType => {
                // Maybe it's useless for config and log types
                // as re-publishing metadata for config and log will trigger republishing 118/119.
                // Also, we don't keep any cache for log/config types where mapper can access.
            }
            SignalType::LogType => {}
            SignalType::Health => {
                // Do the same as `cmd/health/check`
            }
            SignalType::Custom(_) => {}
        }

        Ok(messages)
    }

    fn send_child_supported_operation_messages(
        &mut self,
    ) -> Result<Vec<MqttMessage>, ConversionError> {
        let mut messages = Vec::new();

        let mut child_supported_operations_messages: Vec<MqttMessage> = Vec::new();
        for child_xid in self.supported_operations.get_child_xids() {
            let message = self.load_and_create_supported_operations_messages(&child_xid)?;
            child_supported_operations_messages.push(message);
        }
        messages.append(&mut child_supported_operations_messages);

        Ok(messages)
    }
}
