*** Settings ***
Resource    ../../../resources/common.resource
Library    Cumulocity
Library    ThinEdgeIO

Test Tags    theme:c8y    theme:troubleshooting    theme:plugins
Test Setup    Custom Setup
Test Teardown    Get Logs

*** Test Cases ***

Install/uninstall c8y-remote-access-plugin
    Device Should Have Installed Software    c8y-remote-access-plugin
    File Should Exist    /etc/tedge/operations/c8y/c8y_RemoteAccessConnect
    Execute Command    dpkg -r c8y-remote-access-plugin
    File Should Not Exist    /etc/tedge/operations/c8y/c8y_RemoteAccessConnect

Execute ssh command using PASSTHROUGH
    ${KEY_FILE}=    Configure SSH
    Add Remote Access Passthrough Configuration
    ${stdout}=    Execute Remote Access Command    command=tedge --version    exp_exit_code=0    user=root    key_file=${KEY_FILE}
    Should Match Regexp    ${stdout}    tedge .+

Remote access session is independent from mapper
    ${KEY_FILE}=    Configure SSH
    Add Remote Access Passthrough Configuration

    # Restart mapper
    ${stdout}=    Execute Remote Access Command    command=systemctl restart tedge-mapper-c8y && sleep 2 && echo Successfully restarted tedge-mapper-c8y via remote access    exp_exit_code=0    user=root    key_file=${KEY_FILE}
    Should Contain    ${stdout}    Successfully restarted tedge-mapper-c8y via remote access

    # Restart agent
    ${stdout}=    Execute Remote Access Command    command=systemctl restart tedge-mapper-c8y && sleep 2 && echo Successfully restarted tedge-agent via remote access    exp_exit_code=0    user=root    key_file=${KEY_FILE}
    Should Contain    ${stdout}    Successfully restarted tedge-agent via remote access

    # Uninstall most components (this is a bit over the top...but used to check how independent is the process)
    ${stdout}=    Execute Remote Access Command    command=apt-get remove -y tedge-agent tedge-apt-plugin tedge-mapper tedge-watchdog && sleep 2 && echo Successfully removed thin-edge.io components via remote access    exp_exit_code=0    user=root    key_file=${KEY_FILE}
    Should Contain    ${stdout}    Successfully removed thin-edge.io components via remote access

*** Keywords ***

Custom Setup
    ${DEVICE_SN}=    Setup
    Set Suite Variable    $DEVICE_SN
    Device Should Exist    ${DEVICE_SN}

    # TODO: The c8y_RemoteAccessConnect should be set via the c8y-remote-access-plugin binary
    Transfer To Device    ${CURDIR}/c8y_RemoteAccessConnect    /etc/tedge/operations/c8y/c8y_RemoteAccessConnect

    Enable Service    ssh
    Start Service    ssh
