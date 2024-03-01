use crate::cli::device::create::DeviceCreateCmd;
use crate::cli::device::remove::DeviceRemoveCmd;
use crate::command::BuildCommand;
use crate::command::BuildContext;
use crate::command::Command;
use crate::ConfigError;

const CLIENT_PREFIX: &str = "tedge-device-rm";

#[derive(clap::Subcommand, Debug)]
pub enum TEdgeDeviceCli {
    /// Create a child device
    Create {
        /// The external ID of a child device to be removed
        #[clap(long = "device-id", short = 'd')]
        id: String,

        #[clap(short = 'a')]
        create_alarm: bool,

        #[clap(short = 'm')]
        create_measurement: bool,
    },

    /// Remove a child device
    Remove {
        /// The external ID of a child device to be removed
        #[clap(long = "device-id", short = 'd')]
        id: String,
    },
}

impl BuildCommand for TEdgeDeviceCli {
    fn build_command(self, context: BuildContext) -> Result<Box<dyn Command>, ConfigError> {
        let config = context.config_repository.load()?;
        let auth_config = config.mqtt_client_auth_config();

        let cmd = match self {
            TEdgeDeviceCli::Remove { id } => DeviceRemoveCmd {
                host: config.mqtt.client.host.clone(),
                port: config.mqtt.client.port.into(),
                topics: vec![
                    format!("{}/device/{}/#", config.mqtt.topic_root.to_string(), id),
                    format!(
                        "c8y-internal/alarms/{}/device/{}/#",
                        config.mqtt.topic_root.to_string(),
                        id
                    ),
                ],
                client_id: format!("{}-{}", CLIENT_PREFIX, std::process::id()),
                ca_file: auth_config.ca_file,
                ca_dir: auth_config.ca_dir,
                client_auth_config: auth_config.client,
            }
            .into_boxed(),
            TEdgeDeviceCli::Create {
                id,
                create_alarm,
                create_measurement,
            } => DeviceCreateCmd {
                host: config.mqtt.client.host.clone(),
                port: config.mqtt.client.port.into(),
                client_id: format!("{}-{}", CLIENT_PREFIX, std::process::id()),
                ca_file: auth_config.ca_file,
                ca_dir: auth_config.ca_dir,
                client_auth_config: auth_config.client,
                id,
                create_measurement,
                create_alarm,
            }
            .into_boxed(),
        };

        Ok(cmd)
    }
}
