*** Settings ***
Resource    ../../../resources/common.resource
Library    Cumulocity
Library    ThinEdgeIO

Test Tags    theme:c8y    theme:troubleshooting    theme:plugins
Test Setup    Custom Setup
Test Teardown    Get Logs

*** Test Cases ***

Playground
    Create child device    child100


Remove a child device via CLI
    Create child device    child1
    Sleep    2s
    Execute Command    tedge device remove -d child1
    Sleep    2s
    Run Keyword And Expect Error    *    External Identity Should Exist    ${DEVICE_SN}:device:child1


Remove a child device via custom tedge_DeleteChild operation
    Create child device    child2
    Sleep    2s
    Device Should Exist    ${DEVICE_SN}
    ${operation}=    Cumulocity.Create Operation    fragments={"tedge_DeleteChild":{"id":"child2"}}    description=Remove a child device
    Sleep    5s
    Operation Should Be SUCCESSFUL    ${operation}
    Run Keyword And Expect Error    *    External Identity Should Exist    ${DEVICE_SN}:device:child2


Remove a child device via c8y_Command plugin
    Create child device    child3
    Sleep    2s
    Device Should Exist    ${DEVICE_SN}
    ${operation}=    Cumulocity.Execute Shell Command    tedge device remove -d child3
    Sleep    2s
    Operation Should Be SUCCESSFUL    ${operation}
    Run Keyword And Expect Error    *    External Identity Should Exist    ${DEVICE_SN}:device:child3


*** Keywords ***

Create child device
    [Arguments]    ${var}
    Execute Command    tedge mqtt pub te/device/${var}///m/ '{"temperature": 10}'
    Execute Command    tedge mqtt pub te/device/${var}///a/alarm-type '{"severity":"minor","text": "someone logged-in"}'
    Execute Command    tedge mqtt pub --retain te/device/${var}///cmd/some_command '{}'
    Execute Command    tedge mqtt pub --retain te/device/${var}///cmd/some_command/1234 '{}'
    Device Should Exist    ${DEVICE_SN}:device:${var}


Custom Setup
    ${DEVICE_SN}=    Setup
    Set Suite Variable    $DEVICE_SN
    Device Should Exist    ${DEVICE_SN}
    Execute Command    tedge config set c8y.smartrest.templates e2024
    ThinEdgeIO.Transfer To Device    ${CURDIR}/command_handler.*    /etc/tedge/operations/command
    ThinEdgeIO.Transfer To Device    ${CURDIR}/tedge_delete_child.sh    /etc/tedge/operations/
    ThinEdgeIO.Transfer To Device    ${CURDIR}/c8y_Command*         /etc/tedge/operations/c8y/
    ThinEdgeIO.Transfer To Device    ${CURDIR}/tedge_DeleteChild         /etc/tedge/operations/c8y/
    ThinEdgeIO.Restart Service    tedge-agent
    ThinEdgeIO.Disconnect Then Connect Mapper    c8y
