use crate::FirmwareManagerConfig;

pub struct DownloadManager {
    config: FirmwareManagerConfig,
}

impl DownloadManager {
    pub fn new(config: FirmwareManagerConfig) -> Self {
        Self { config }
    }
}
