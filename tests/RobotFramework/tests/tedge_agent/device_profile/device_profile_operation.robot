*** Settings ***
Resource            ../../../resources/common.resource
Library             ThinEdgeIO
Library             Cumulocity
Library             OperatingSystem
Library             Collections

Force Tags          theme:tedge_agent
Suite Setup         Custom Setup
Test Setup          Custom Test Setup
Test Teardown       Get Logs

*** Test Cases ***

Device profile is included in supported operations
    ${CAPABILITY_MESSAGE}=    Execute Command    timeout 1 tedge mqtt sub 'te/device/main///cmd/device_profile'    strip=${True}    ignore_exit_code=${True}
    Should Be Equal    ${CAPABILITY_MESSAGE}    [te/device/main///cmd/device_profile] {}
    Should Contain Supported Operations    c8y_DeviceProfile


Send device profile operation from Cumulocity IoT
    ${config_url}=    Create Inventory Binary    tedge-configuration-plugin    tedge-configuration-plugin    file=${CURDIR}/tedge-configuration-plugin.toml

    ${PROFILE_NAME}=    Set Variable    Test Profile
    ${PROFILE_PAYLOAD}=    Catenate    SEPARATOR=\n    {
    ...    "c8y_DeviceProfile":{
    # ...        "firmware":[
    # ...            {
    # ...                "name":"tedge-core",
    # ...                "version":"1.0.0",
    # ...                "url":""
    # ...            }
    # ...        ],
    ...        "software":[
    ...            {
    ...                "name":"jq",
    ...                "action":"install",
    ...                "version":"latest",
    ...                "url":""
    ...            },
    ...            {
    ...                "name":"tree",
    ...                "action":"install",
    ...                "version":"latest",
    ...                "url":""
    ...            }
    ...        ],
    ...        "configuration":[
    ...            {
    ...                "name":"tedge-configuration-plugin",
    ...                "type":"tedge-configuration-plugin",
    ...                "url":"${config_url}"
    ...            }
    ...        ]
    ...    }}

    ${operation}=    Create And Apply Device Profile    ${PROFILE_NAME}    ${PROFILE_PAYLOAD}    ${DEVICE_SN}
    ${operation}=    Operation Should Be SUCCESSFUL    ${operation}
    ${profile_id}=    Get From Dictionary    ${operation}    profileId
    Managed Object Should Have Fragment Values    c8y_Profile.profileName\=${PROFILE_NAME}    c8y_Profile.profileExecuted\=true
    Execute Command    dpkg -l | grep jq
    Execute Command    dpkg -l | grep tree
    [Teardown]    Delete Managed Object    ${profile_id}

Send device profile operation locally
    ${config_url}=    Set Variable    http://localhost:8000/tedge/file-transfer/main/config_update/robot-123

    Execute Command     curl -X PUT --data-binary "bad toml" "${config_url}"

    ${payload}=    Catenate    SEPARATOR=\n    
    ...    {
    ...      "status": "init",
    ...      "name": "dev-profile",
    ...      "version": "v2",
    ...      "operations": [
    # ...        {
    # ...          "operation": "firmware_update",
    # ...          "skip": true,
    # ...          "payload": {
    # ...            "name": "core-image-tedge-rauc",
    # ...            "remoteUrl": "https://abc.com/some/firmware/url",
    # ...            "version": "20240430.1139"
    # ...          }
    # ...        },
    ...        {
    ...          "operation": "software_update",
    ...          "skip": false,
    ...          "payload": {
    ...            "updateList": [
    ...              {
    ...                "type": "apt",
    ...                "modules": [
    ...                  {
    ...                    "name": "yq",
    ...                    "version": "latest",
    ...                    "action": "install"
    ...                  },
    ...                  {
    ...                    "name": "jo",
    ...                    "version": "latest",
    ...                    "action": "install"
    ...                  }
    ...                ]
    ...              }
    ...            ]
    ...          }
    ...        },
    ...        {
    ...          "operation": "config_update",
    ...          "skip": false,
    ...          "payload": {
    ...            "type": "tedge-configuration-plugin",
    ...            "tedgeUrl": "${config_url}",
    ...            "remoteUrl": ""
    ...          }
    ...        },
    ...        {
    ...          "operation": "restart",
    ...          "skip": false,
    ...          "payload": {}
    ...        },
    ...        {
    ...          "operation": "software_update",
    ...          "skip": false,
    ...          "payload": {
    ...            "updateList": [
    ...              {
    ...                "type": "apt",
    ...                "modules": [
    ...                  {
    ...                    "name": "rolldice",
    ...                    "version": "latest",
    ...                    "action": "install"
    ...                  }
    ...                ]
    ...              }
    ...            ]
    ...          }
    ...        }
    ...      ]
    ...    }

    Execute Command    tedge mqtt pub --retain 'te/device/main///cmd/device_profile/robot-123' '${payload}'
    ${cmd_messages}    Should Have MQTT Messages    te/device/main///cmd/device_profile/robot-123    message_pattern=.*successful.*   maximum=1    timeout=60

    # Validate installed packages
    Execute Command    dpkg -l | grep rolldice
    Execute Command    dpkg -l | grep yq
    Execute Command    dpkg -l | grep jo

    # Validate updated config file
    Execute Command    grep "bad toml" /etc/tedge/plugins/tedge-configuration-plugin.toml

    [Teardown]    Execute Command    tedge mqtt pub --retain te/device/main///cmd/device_profile/robot-123 ''

*** Keywords ***

Custom Test Setup
    Execute Command    cmd=echo 'tedge ALL = (ALL) NOPASSWD: /usr/bin/tedge, /usr/bin/systemctl, /etc/tedge/sm-plugins/[a-zA-Z0-9]*, /bin/sync, /sbin/init, /sbin/shutdown, /usr/bin/on_shutdown.sh, /usr/bin/tedge-write /etc/*' > /etc/sudoers.d/tedge

Custom Setup
    ${DEVICE_SN}=    Setup
    Set Suite Variable    $DEVICE_SN
    Device Should Exist                      ${DEVICE_SN}

    Copy Configuration Files
    Restart Service    tedge-agent

    # setup repos so that packages can be installed from them
    Execute Command    curl -1sLf 'https://dl.cloudsmith.io/public/thinedge/tedge-main/setup.deb.sh' | sudo -E bash
    Execute Command    curl -1sLf 'https://dl.cloudsmith.io/public/thinedge/community/setup.deb.sh' | sudo -E bash
    

Copy Configuration Files
    ThinEdgeIO.Transfer To Device    ${CURDIR}/firmware_update.toml      /etc/tedge/operations/
    ThinEdgeIO.Transfer To Device    ${CURDIR}/tedge_operator_helper.sh         /etc/tedge/operations/
