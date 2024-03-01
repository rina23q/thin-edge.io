use crate::cli::mqtt::MqttError;
use crate::command::Command;
use camino::Utf8PathBuf;
use certificate::parse_root_certificate;
use rumqttc::tokio_rustls::rustls::ClientConfig;
use rumqttc::tokio_rustls::rustls::RootCertStore;
use rumqttc::Client;
use rumqttc::Connection;
use rumqttc::Event;
use rumqttc::Incoming;
use rumqttc::MqttOptions;
use rumqttc::Packet;
use rumqttc::QoS;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tedge_config::MqttAuthClientConfig;

const MAX_PACKET_SIZE: usize = 10 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(1);

/// Remove a child device
#[derive(Debug, Clone)]
pub struct DeviceRemoveCmd {
    pub host: String,
    pub port: u16,
    pub topics: Vec<String>,
    pub client_id: String,
    pub ca_file: Option<Utf8PathBuf>,
    pub ca_dir: Option<Utf8PathBuf>,
    pub client_auth_config: Option<MqttAuthClientConfig>,
}

impl Command for DeviceRemoveCmd {
    fn description(&self) -> String {
        format!("Remove a child device.")
    }

    fn execute(&self) -> anyhow::Result<()> {
        let (sender, receiver) = mpsc::channel();
        let device = self.clone();

        let _join_handle = thread::spawn(move || {
            sender.send(remove_child(&device)).unwrap();
        });

        match receiver.recv_timeout(TIMEOUT) {
            Ok(_) => {}
            Err(_) => {}
        };

        Ok(())
    }
}

fn remove_child(cmd: &DeviceRemoveCmd) -> Result<(), MqttError> {
    let (mut client, mut connection) = cmd.get_connections()?;

    for event in connection.iter() {
        match event {
            Ok(Event::Incoming(Packet::Publish(message))) => {
                if message.retain {
                    eprintln!("Cleared: {}", message.topic);
                    client
                        .publish(message.topic, QoS::AtLeastOnce, true, "")
                        .unwrap();
                }
            }
            Ok(Event::Incoming(Incoming::Disconnect)) => {
                eprintln!("INFO: Disconnected");
                break;
            }
            Ok(Event::Incoming(Packet::ConnAck(_))) => {
                eprintln!("INFO: Connected");
                for topic in &cmd.topics {
                    client.subscribe(topic, QoS::AtLeastOnce)?
                }
            }
            Err(err) => {
                let err_msg = err.to_string();

                eprintln!("ERROR: {}", err_msg);
                thread::sleep(Duration::from_secs(1));
            }
            _ => {}
        }
    }

    Ok(())
}

impl DeviceRemoveCmd {
    fn get_connections(&self) -> Result<(Client, Connection), MqttError> {
        let mut options = MqttOptions::new(self.client_id.as_str(), &self.host, self.port.clone());
        options.set_clean_session(true);
        options.set_max_packet_size(MAX_PACKET_SIZE, MAX_PACKET_SIZE);

        if self.ca_file.is_some() || self.ca_dir.is_some() {
            let mut root_store = RootCertStore::empty();

            if let Some(ca_file) = &self.ca_file {
                parse_root_certificate::add_certs_from_file(&mut root_store, ca_file)?;
            }

            if let Some(ca_dir) = &self.ca_dir {
                parse_root_certificate::add_certs_from_directory(&mut root_store, ca_dir)?;
            }

            const INSECURE_MQTT_PORT: u16 = 1883;
            const SECURE_MQTT_PORT: u16 = 8883;

            if self.port == INSECURE_MQTT_PORT && !root_store.is_empty() {
                eprintln!(
                    "Warning: Connecting on port 1883 for insecure MQTT using a TLS connection"
                );
            }
            if self.port == SECURE_MQTT_PORT && root_store.is_empty() {
                eprintln!(
                    "Warning: Connecting on port 8883 for secure MQTT with no CA certificates"
                );
            }

            let tls_config = ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store);

            let tls_config = if let Some(client_auth) = self.client_auth_config.as_ref() {
                let client_cert = parse_root_certificate::read_cert_chain(&client_auth.cert_file)?;
                let client_key = parse_root_certificate::read_pvt_key(&client_auth.key_file)?;
                tls_config.with_client_auth_cert(client_cert, client_key)?
            } else {
                tls_config.with_no_client_auth()
            };

            options.set_transport(rumqttc::Transport::tls_with_config(tls_config.into()));
        }

        Ok(Client::new(options, 10))
    }
}
