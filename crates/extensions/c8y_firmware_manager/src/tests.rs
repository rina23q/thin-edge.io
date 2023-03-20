use super::*;
use c8y_api::smartrest::topic::C8yTopic;
use mqtt_channel::Topic;
use std::str::from_utf8;
use std::time::Duration;
use tedge_actors::Actor;
use tedge_actors::DynError;
use tedge_actors::ReceiveMessages;
use tedge_actors::SimpleMessageBox;
use tedge_actors::SimpleMessageBoxBuilder;
use tedge_config::IpAddress;
use tedge_test_utils::fs::TempTedgeDir;
use tokio::time::timeout;

const CHILD_DEVICE_ID: &str = "child-device";
const FIRMWARE_NAME: &str = "fw-name";
const FIRMWARE_VERSION: &str = "fw-version";
const TEST_TIMEOUT_MS: Duration = Duration::from_millis(5000);
const DEFAULT_REQUEST_TIMEOUT_SEC: Duration = Duration::from_secs(3600);

// TODO: mockito???
const DOWNLOAD_URL: &str = "http://test.domain.com";

#[tokio::test]
async fn handle_request_dir_cache_not_found() -> Result<(), DynError> {
    let ttd = TempTedgeDir::new();
    ttd.dir("file-transfer");
    ttd.dir("firmware");

    let (mut mqtt_message_box, mut c8y_proxy_message_box, mut _timer_message_box) =
        spawn_firmware_manager(&ttd).await?;

    // On startup, two messages should be sent by firmware manager.
    let _pending_ops_msg = mqtt_message_box.recv().await.unwrap();
    let _health_check_msg = mqtt_message_box.recv().await.unwrap();

    // Publish firmware update operation to child device.
    let c8y_firmware_update_msg = MqttMessage::new(
        &Topic::new_unchecked("c8y/s/ds"),
        format!("515,{CHILD_DEVICE_ID},{FIRMWARE_NAME},{FIRMWARE_VERSION},{DOWNLOAD_URL}"),
    );
    mqtt_message_box.send(c8y_firmware_update_msg).await?;

    // dbg!(&from_utf8(message1.payload.as_slice()));

    // Assert EXECUTING SmartREST MQTT message
    let expected_message =
        MqttMessage::new(&Topic::new_unchecked("c8y/s/us"), "501,c8y_Firmware\n");
    let next_message = timeout(TEST_TIMEOUT_MS, mqtt_message_box.recv()).await;
    assert_eq!(next_message, Ok(Some(expected_message)));

    Ok(())
}

async fn spawn_firmware_manager(
    tedge_temp_dir: &TempTedgeDir,
) -> Result<
    (
        SimpleMessageBox<MqttMessage, MqttMessage>,
        SimpleMessageBox<C8YRestRequest, C8YRestResult>,
        SimpleMessageBox<OperationTimer, OperationTimeout>,
    ),
    DynError,
> {
    let device_id = "parent-device";
    let tedge_host: IpAddress = "127.0.0.1".try_into().unwrap();
    let c8y_host = "test.c8y.io";
    let mqtt_port = 1234;
    let tedge_http_port = 8765;

    let config = FirmwareManagerConfig::new(
        device_id.to_string(),
        tedge_host.into(),
        tedge_http_port,
        tedge_temp_dir.to_path_buf(),
        tedge_temp_dir.to_path_buf(),
        DEFAULT_REQUEST_TIMEOUT_SEC,
    );

    let mut mqtt_builder: SimpleMessageBoxBuilder<MqttMessage, MqttMessage> =
        SimpleMessageBoxBuilder::new("MQTT", 5);
    let mut c8y_proxy_builder: SimpleMessageBoxBuilder<C8YRestRequest, C8YRestResult> =
        SimpleMessageBoxBuilder::new("C8Y", 1);
    let mut timer_builder: SimpleMessageBoxBuilder<OperationTimer, OperationTimeout> =
        SimpleMessageBoxBuilder::new("Timer", 5);

    let mut firmware_manager_builder = FirmwareManagerBuilder::new(config);

    firmware_manager_builder.with_c8y_http_proxy(&mut c8y_proxy_builder)?;
    firmware_manager_builder.with_mqtt_connection(&mut mqtt_builder)?;
    firmware_manager_builder.with_timer(&mut timer_builder)?;

    let mqtt_message_box = mqtt_builder.build();
    let c8y_proxy_message_box = c8y_proxy_builder.build();
    let timer_message_box = timer_builder.build();

    let (actor, message_box) = firmware_manager_builder.build();
    let _join_handle = tokio::spawn(async move { actor.run(message_box).await });

    Ok((mqtt_message_box, c8y_proxy_message_box, timer_message_box))
}
