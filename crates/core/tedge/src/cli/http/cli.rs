use crate::cli::http::command::HttpCommand;
use crate::command::BuildCommand;
use crate::command::BuildContext;
use crate::command::Command;
use crate::ConfigError;
use anyhow::anyhow;
use anyhow::Error;
use certificate::CloudRootCerts;
use reqwest::blocking;
use reqwest::Identity;
use tedge_config::OptionalConfig;
use tedge_config::ProfileName;

#[derive(clap::Subcommand, Debug)]
pub enum TEdgeHttpCli {
    /// POST content to thin-edge local HTTP servers
    Post {
        /// Target URI
        uri: String,

        /// Content to post
        content: String,

        /// Optional c8y cloud profile
        #[clap(long)]
        profile: Option<ProfileName>,
    },

    /// GET content from thin-edge local HTTP servers
    Get {
        /// Source URI
        uri: String,

        /// Optional c8y cloud profile
        #[clap(long)]
        profile: Option<ProfileName>,
    },
}

impl BuildCommand for TEdgeHttpCli {
    fn build_command(self, context: BuildContext) -> Result<Box<dyn Command>, ConfigError> {
        let config = context.load_config()?;
        let uri = self.uri();

        let (protocol, host, port) = if uri.starts_with("/c8y") {
            let c8y_config = config.c8y.try_get(self.c8y_profile())?;
            let client = &c8y_config.proxy.client;
            let protocol = https_if_some(&c8y_config.proxy.cert_path);
            (protocol, client.host.clone(), client.port)
        } else if uri.starts_with("/tedge") {
            let client = &config.http.client;
            let protocol = https_if_some(&config.http.cert_path);
            (protocol, client.host.clone(), client.port)
        } else {
            return Err(anyhow!("Not a local HTTP uri: {uri}").into());
        };

        let url = format!("{protocol}://{host}:{port}{uri}");
        let verb_url = format!("{} {url}", self.verb());
        let identity = config.http.client.auth.identity()?;
        let client = http_client(config.cloud_root_certs(), identity.as_ref())?;

        let request = match self {
            TEdgeHttpCli::Post { content, .. } => client
                .post(url)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .body(content),
            TEdgeHttpCli::Get { .. } => client.get(url).header("Accept", "application/json"),
        };

        Ok(HttpCommand {
            url: verb_url,
            request,
        }
        .into_boxed())
    }
}

impl TEdgeHttpCli {
    fn uri(&self) -> &str {
        match self {
            TEdgeHttpCli::Post { uri, .. } | TEdgeHttpCli::Get { uri, .. } => uri.as_ref(),
        }
    }

    fn verb(&self) -> &str {
        match self {
            TEdgeHttpCli::Post { .. } => "POST",
            TEdgeHttpCli::Get { .. } => "GET",
        }
    }

    fn c8y_profile(&self) -> Option<&ProfileName> {
        match self {
            TEdgeHttpCli::Post { profile, .. } | TEdgeHttpCli::Get { profile, .. } => {
                profile.as_ref()
            }
        }
    }
}

fn https_if_some<T>(cert_path: &OptionalConfig<T>) -> &'static str {
    cert_path.or_none().map_or("http", |_| "https")
}

fn http_client(
    root_certs: CloudRootCerts,
    identity: Option<&Identity>,
) -> Result<blocking::Client, Error> {
    let builder = root_certs.blocking_client_builder();
    let builder = if let Some(identity) = identity {
        builder.identity(identity.clone())
    } else {
        builder
    };
    Ok(builder.build()?)
}
