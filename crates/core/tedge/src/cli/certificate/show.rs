use crate::command::Command;
use crate::log::MaybeFancy;
use anyhow::Context;
use camino::Utf8PathBuf;
use certificate::PemCertificate;
use certificate::ValidityStatus;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use yansi::Paint;

macro_rules! print_async {
    ($out:expr, $fmt:literal) => (
        let _ = $out.write_all($fmt.as_bytes()).await;
    );
    ($out:expr, $fmt:literal, $($arg:tt)*) => (
        let _ = $out.write_all(format!($fmt, $($arg)*).as_bytes()).await;
    );
}

/// Show the device certificate, if any
pub struct ShowCertCmd {
    /// The path where the device certificate is stored
    pub cert_path: Utf8PathBuf,

    /// Minimum validity duration bellow which a new certificate should be requested
    pub minimum: Duration,
}

#[async_trait::async_trait]
impl Command for ShowCertCmd {
    fn description(&self) -> String {
        "show the device certificate".into()
    }

    async fn execute(&self) -> Result<(), MaybeFancy<anyhow::Error>> {
        self.show_certificate().await?;
        Ok(())
    }
}

impl ShowCertCmd {
    pub async fn show_certificate(&self) -> Result<(), anyhow::Error> {
        let cert_path = &self.cert_path;
        let cert = tokio::fs::read_to_string(cert_path)
            .await
            .with_context(|| format!("reading certificate from {cert_path}"))?;
        let pem = PemCertificate::from_pem_string(&cert)
            .with_context(|| format!("decoding certificate from {cert_path}"))?;

        let mut stdout = tokio::io::stdout();
        print_async!(stdout, "Certificate:   {}\n", self.cert_path);
        print_async!(stdout, "Subject:       {}\n", pem.subject()?);
        print_async!(stdout, "Issuer:        {}\n", pem.issuer()?);
        print_async!(
            stdout,
            "Status:        {}\n",
            display_status(pem.still_valid()?, self.minimum)
        );
        print_async!(stdout, "Valid from:    {}\n", pem.not_before()?);
        print_async!(stdout, "Valid until:   {}\n", pem.not_after()?);
        print_async!(
            stdout,
            "Serial number: {} (0x{})\n",
            pem.serial()?,
            pem.serial_hex()?
        );
        print_async!(stdout, "Thumbprint:    {}\n", pem.thumbprint()?);
        let _ = stdout.flush().await;
        Ok(())
    }
}

fn display_status(status: ValidityStatus, minimum: Duration) -> String {
    let text = match status {
        ValidityStatus::Valid { expired_in } => {
            format!(
                "VALID (expires in: {})",
                humantime::format_duration(expired_in)
            )
        }
        ValidityStatus::Expired { since } => {
            format!("EXPIRED (since: {})", humantime::format_duration(since))
        }
        ValidityStatus::NotValidYet { valid_in } => {
            format!(
                "NOT VALID YET (will be in: {})",
                humantime::format_duration(valid_in)
            )
        }
    };

    match status {
        ValidityStatus::Valid { expired_in } if expired_in > minimum => {
            format!("{}", text.green())
        }
        ValidityStatus::Valid { .. } => format!("{}", text.yellow()),
        ValidityStatus::Expired { .. } => format!("{}", text.red()),
        ValidityStatus::NotValidYet { .. } => format!("{}", text.red()),
    }
}
