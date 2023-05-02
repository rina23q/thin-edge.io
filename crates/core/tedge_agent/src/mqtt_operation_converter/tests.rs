use crate::mqtt_operation_converter::builder::MqttOperationConverterBuilder;
use mqtt_channel::Topic;
use std::time::Duration;
use tedge_actors::test_helpers::MessageReceiverExt;
use tedge_actors::test_helpers::TimedMessageBox;
use tedge_actors::Actor;
use tedge_actors::Builder;
use tedge_actors::DynError;
use tedge_actors::MessageReceiver;
use tedge_actors::Sender;
use tedge_actors::SimpleMessageBox;
use tedge_actors::SimpleMessageBoxBuilder;
use tedge_api::RestartOperationRequest;
use tedge_api::RestartOperationResponse;
use tedge_api::SoftwareListRequest;
use tedge_api::SoftwareListResponse;
use tedge_api::SoftwareUpdateRequest;
use tedge_api::SoftwareUpdateResponse;
use tedge_mqtt_ext::MqttMessage;

const TEST_TIMEOUT_MS: Duration = Duration::from_millis(5000);

#[tokio::test]
async fn convert_incoming_software_list_request() -> Result<(), DynError> {
    // Spawn incoming mqtt message converter
    let (mut software_list_box, _software_update_box, _restart_box, mut mqtt_box) =
        spawn_mqtt_operation_converter().await?;

    // Simulate SoftwareList MQTT message received.
    let mqtt_message = MqttMessage::new(
        &Topic::new_unchecked("tedge/commands/req/software/list"),
        r#"{"id": "random"}"#,
    );
    mqtt_box.send(mqtt_message).await?;

    // Assert SoftwareListRequest
    software_list_box
        .assert_received([SoftwareListRequest {
            id: "random".to_string(),
        }])
        .await;
    Ok(())
}

#[tokio::test]
async fn convert_incoming_software_update_request() -> Result<(), DynError> {
    // Spawn incoming mqtt message converter
    let (_software_list_box, mut software_update_box, _restart_box, mut mqtt_box) =
        spawn_mqtt_operation_converter().await?;

    // Simulate SoftwareUpdate MQTT message received.
    let mqtt_message = MqttMessage::new(
        &Topic::new_unchecked("tedge/commands/req/software/update"),
        r#"{"id":"1234","updateList":[{"type":"debian","modules":[{"name":"debian1","version":"0.0.1","action":"install"}]}]}"#,
    );
    mqtt_box.send(mqtt_message).await?;

    // TODO: Assert SoftwareListRequest properly?
    let aaa = software_update_box.recv().await.unwrap();
    dbg!(&aaa);

    Ok(())
}

#[tokio::test]
async fn convert_incoming_restart_request() -> Result<(), DynError> {
    // Spawn incoming mqtt message converter
    let (_software_list_box, _software_update_box, mut restart_box, mut mqtt_box) =
        spawn_mqtt_operation_converter().await?;

    // Simulate Restart MQTT message received.
    let mqtt_message = MqttMessage::new(
        &Topic::new_unchecked("tedge/commands/req/control/restart"),
        r#"{"id": "random"}"#,
    );
    mqtt_box.send(mqtt_message).await?;

    // Assert RestartOperationRequest
    restart_box
        .assert_received([RestartOperationRequest {
            id: "random".to_string(),
        }])
        .await;

    Ok(())
}

#[tokio::test]
async fn convert_outgoing_software_list_response() -> Result<(), DynError> {
    // Spawn outgoing mqtt message converter
    let (mut software_list_box, _software_update_box, _restart_box, mut mqtt_box) =
        spawn_mqtt_operation_converter().await?;

    // Simulate SoftwareList response message received.
    let software_list_request = SoftwareListRequest::new_with_id("1234");
    let software_list_response = SoftwareListResponse::new(&software_list_request);
    software_list_box
        .send(software_list_response.into())
        .await?;

    let aaaa = mqtt_box.recv().await;
    dbg!(&aaaa);

    Ok(())
}

// TODO: convert_outgoing_software_update_response

#[tokio::test]
async fn convert_outgoing_restart_response() -> Result<(), DynError> {
    // Spawn outgoing mqtt message converter
    let (_software_list_box, _software_update_box, mut restart_box, mut mqtt_box) =
        spawn_mqtt_operation_converter().await?;

    // Simulate SoftwareList response message received.
    let executing_response = RestartOperationResponse::new(&RestartOperationRequest::default());
    restart_box.send(executing_response.into()).await?;

    let aaaa = mqtt_box.recv().await;
    dbg!(&aaaa);

    Ok(())
}

async fn spawn_mqtt_operation_converter() -> Result<
    (
        TimedMessageBox<SimpleMessageBox<SoftwareListRequest, SoftwareListResponse>>,
        TimedMessageBox<SimpleMessageBox<SoftwareUpdateRequest, SoftwareUpdateResponse>>,
        TimedMessageBox<SimpleMessageBox<RestartOperationRequest, RestartOperationResponse>>,
        TimedMessageBox<SimpleMessageBox<MqttMessage, MqttMessage>>,
    ),
    DynError,
> {
    let mut software_list_builder: SimpleMessageBoxBuilder<
        SoftwareListRequest,
        SoftwareListResponse,
    > = SimpleMessageBoxBuilder::new("SoftwareList", 5);
    let mut software_update_builder: SimpleMessageBoxBuilder<
        SoftwareUpdateRequest,
        SoftwareUpdateResponse,
    > = SimpleMessageBoxBuilder::new("SoftwareUpdate", 5);
    let mut restart_builder: SimpleMessageBoxBuilder<
        RestartOperationRequest,
        RestartOperationResponse,
    > = SimpleMessageBoxBuilder::new("Restart", 5);
    let mut mqtt_builder: SimpleMessageBoxBuilder<MqttMessage, MqttMessage> =
        SimpleMessageBoxBuilder::new("MQTT", 5);

    let converter_actor_builder = MqttOperationConverterBuilder::new(
        &mut software_list_builder,
        &mut software_update_builder,
        &mut restart_builder,
        &mut mqtt_builder,
    );

    let software_list_box = software_list_builder.build().with_timeout(TEST_TIMEOUT_MS);
    let software_update_box = software_update_builder
        .build()
        .with_timeout(TEST_TIMEOUT_MS);
    let restart_box = restart_builder.build().with_timeout(TEST_TIMEOUT_MS);
    let mqtt_message_box = mqtt_builder.build().with_timeout(TEST_TIMEOUT_MS);

    let mut converter_actor = converter_actor_builder.build();
    tokio::spawn(async move { converter_actor.run().await });

    Ok((
        software_list_box,
        software_update_box,
        restart_box,
        mqtt_message_box,
    ))
}