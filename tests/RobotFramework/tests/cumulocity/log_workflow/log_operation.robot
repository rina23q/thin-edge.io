*** Settings ***
Resource            ../../../resources/common.resource
Library             Cumulocity
Library             DateTime
Library             ThinEdgeIO
Library             String
Library             OperatingSystem

Test Setup         Setup
Test Teardown       Get Logs

Test Tags           theme:c8y    theme:log


*** Test Cases ***
Prepare workflow environment
    ThinEdgeIO.Transfer To Device    ${CURDIR}/custom_log_workflow.toml    /etc/tedge/operations/
    ThinEdgeIO.Transfer To Device    ${CURDIR}/log_upload.sh    /etc/tedge/operations/
    Execute Command    chmod +x /etc/tedge/operations/log_upload.sh

    Execute Command    tedge config set agent.enable.log_upload false
    ThinEdgeIO.Restart Service    tedge-agent

    Execute Command    tedge mqtt pub -r 'te/device/main///cmd/log_upload' '{"types":["challenge"]}'

    Sleep    1s