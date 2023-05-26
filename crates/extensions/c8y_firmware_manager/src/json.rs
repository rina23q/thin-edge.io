use crate::error::FirmwareRequestResponseError;
use serde::Deserialize;
use serde::Serialize;
use tedge_api::OperationStatus;
use tedge_mqtt_ext::MqttMessage;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FirmwareInfo {
    pub name: String,
    pub url: String,
    pub version: String,
}

impl FirmwareInfo {
    pub fn new(name: &str, url: &str, version: &str) -> Self {
        Self {
            name: name.to_string(),
            url: url.to_string(),
            version: version.to_string(),
        }
    }
}

impl ToString for FirmwareInfo {
    fn to_string(&self) -> String {
        serde_json::to_string(&self).expect("infallible")
    }
}

// Candidate to be generic later.
#[derive(Deserialize, Debug, Clone)]
pub struct NewFirmwareRequest {
    pub id: String,
    pub device: String,
    #[serde(flatten)]
    pub firmware: FirmwareInfo,
}

impl TryFrom<MqttMessage> for NewFirmwareRequest {
    type Error = FirmwareRequestResponseError;

    fn try_from(value: MqttMessage) -> Result<Self, Self::Error> {
        let payload = value.payload.as_str()?;
        let request: NewFirmwareRequest = serde_json::from_str(payload)?;
        Ok(request)
    }
}

#[derive(Serialize, Debug)]
pub struct OperationStatusPayload {
    pub id: String,
    pub status: OperationStatus,
    pub device: String,
    #[serde(flatten)]
    pub firmware: FirmwareInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl OperationStatusPayload {
    pub fn new(
        id: &str,
        status: OperationStatus,
        device: &str,
        name: &str,
        url: &str,
        version: &str,
    ) -> Self {
        Self {
            id: id.into(),
            status,
            device: device.to_string(),
            firmware: FirmwareInfo::new(name, url, version),
            reason: None,
        }
    }

    pub fn with_reason(self, reason: &str) -> Self {
        Self {
            reason: Some(reason.into()),
            ..self
        }
    }
}

impl ToString for OperationStatusPayload {
    fn to_string(&self) -> String {
        serde_json::to_string(&self).expect("infallible")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use assert_json_diff::assert_json_eq;
    use assert_matches::assert_matches;
    use serde_json::json;

    #[test]
    fn serialize_operation_payload() {
        let operation = OperationStatusPayload::new(
            "id",
            OperationStatus::Executing,
            "device",
            "name",
            "url",
            "version",
        );
        let json = serde_json::to_string(&operation).unwrap();
        dbg!(&json);
    }

    #[test]
    fn serialize_operation_payload_with_reason() {
        let operation = OperationStatusPayload::new(
            "id",
            OperationStatus::Executing,
            "device",
            "name",
            "url",
            "version",
        )
        .with_reason("aaa");
        let json = operation.to_string();
        dbg!(&json);
    }

    #[test]
    fn deserialize_firmware_request() {
        let data = r#"
{
    "id": "50203",
    "name": "simple text",
    "version": "2.0",
    "url": "https://t6352.basic.stage.c8y.io/inventory/binaries/11203",
    "device": "87aa0422-ccb0-4435-a497-117b2f00ea67",
    "unknown": "aaaa",
    "sha256": "aaaaaaaaa",
    "layer": {
        "one": "one"
    }
}"#;
        let value: NewFirmwareRequest = serde_json::from_str(data).unwrap();

        dbg!(&value);
    }
}
