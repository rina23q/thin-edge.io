use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use mqtt_channel::Connection;
use mqtt_channel::TopicFilter;
use mqtt_channel::UnboundedSender;
use tedge_config::C8yUrlSetting;
use tedge_config::ConfigSettingAccessor;
use tedge_config::DeviceIdSetting;
use tedge_config::HttpBindAddressSetting;
use tedge_config::HttpPortSetting;
use tedge_config::IpAddress;
use tedge_config::MqttClientHostSetting;
use tedge_config::MqttClientPortSetting;
use tedge_config::TEdgeConfig;
use tedge_config::TEdgeConfigError;
use tedge_config::TmpPathSetting;

/// Configuration of the Firmware Manager
#[derive(Clone, Debug)]
pub struct FirmwareManagerConfig {
    tedge_device_id: String,
    local_http_host: String,
    cache_dir: PathBuf,
    file_transfer_dir: PathBuf,
    firmware_dir: PathBuf,
}

impl FirmwareManagerConfig {
    pub fn new(
        tedge_device_id: String,
        local_http_address: IpAddress,
        local_http_port: u16,
        persistent_dir: PathBuf,
    ) -> Self {
        let local_http_host = format!("{}:{}", local_http_address, local_http_port);

        // FIXME
        let cache_dir = persistent_dir.join("cache");
        let file_transfer_dir = persistent_dir.join("file-transfer");
        let firmware_dir = persistent_dir.join("firmware");

        Self {
            tedge_device_id,
            local_http_host,
            cache_dir,
            file_transfer_dir,
            firmware_dir,
        }
    }

    pub fn from_tedge_config(tedge_config: &TEdgeConfig) -> Result<Self, TEdgeConfigError> {
        let tedge_device_id = tedge_config.query(DeviceIdSetting)?;
        // let tmp_dir = tedge_config.query(TmpPathSetting)?.into();
        // let mqtt_host = tedge_config.query(MqttClientHostSetting)?;
        // let mqtt_port = tedge_config.query(MqttClientPortSetting)?.into();
        // let c8y_url = tedge_config.query(C8yUrlSetting)?;
        let local_http_address = tedge_config.query(HttpBindAddressSetting)?;
        let local_http_port: u16 = tedge_config.query(HttpPortSetting)?.into();

        let persistent_dir = PathBuf::from("/var/tedge");

        Ok(Self::new(
            tedge_device_id,
            local_http_address,
            local_http_port,
            persistent_dir,
        ))
    }
}
