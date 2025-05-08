use crate::command::Command;
use crate::log::MaybeFancy;
use camino::Utf8Path;
use camino::Utf8PathBuf;
use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use tedge_config::models::SecondsOrHumanTime;
use tedge_utils::file;

pub struct DiagCollectCommand {
    pub plugin_dir: Utf8PathBuf,
    pub output_dir: Utf8PathBuf,
    pub tarball_name: String,
    pub timeout: SecondsOrHumanTime,
}

#[async_trait::async_trait]
impl Command for DiagCollectCommand {
    fn description(&self) -> String {
        "collects diagnostic information".into()
    }

    async fn execute(&self) -> Result<(), MaybeFancy<anyhow::Error>> {
        file::create_directory_with_defaults(&self.output_dir.join(&self.tarball_name))
            .await
            .unwrap();
        let plugins = self.scan_diag_plugins().await?;
        for plugin in plugins {
            let filename = plugin.file_name().unwrap();
            file::create_directory_with_defaults(&self.output_dir.join(&filename))
                .await
                .unwrap();
        }

        Ok(())
    }
}

impl DiagCollectCommand {
    async fn scan_diag_plugins(&self) -> Result<HashSet<Utf8PathBuf>, anyhow::Error> {
        let mut plugins = HashSet::new();
        let mut entries = tokio::fs::read_dir(&self.plugin_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = Utf8PathBuf::from_path_buf(entry.path()).unwrap();
            if path.is_file() && is_executable(&path).await {
                plugins.insert(path);
            }
        }
        Ok(plugins)
    }

    async fn collect_diag_info(plugin_path: &Utf8Path) -> Result<(), anyhow::Error> {
        unimplemented!()
    }
}

async fn is_executable(path: &Utf8Path) -> bool {
    match tokio::fs::metadata(path).await {
        Ok(metadata) => metadata.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}
