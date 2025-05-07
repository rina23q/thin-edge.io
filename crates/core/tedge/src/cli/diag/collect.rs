use crate::command::Command;
use crate::log::MaybeFancy;
use camino::Utf8PathBuf;
use tedge_config::models::SecondsOrHumanTime;

pub struct DiagCollectCommand {
    pub(crate) plugin_dir: Utf8PathBuf,
    pub(crate) output_dir: Utf8PathBuf,
    pub(crate) tarball_name: String,
    pub(crate) timeout: SecondsOrHumanTime,
}

#[async_trait::async_trait]
impl Command for DiagCollectCommand {
    fn description(&self) -> String {
        "collects diagnostic information".into()
    }

    async fn execute(&self) -> Result<(), MaybeFancy<anyhow::Error>> {
        Ok(collect_diag_info().await?)
    }
}

async fn collect_diag_info() -> Result<(), anyhow::Error> {
    unimplemented!()
}
