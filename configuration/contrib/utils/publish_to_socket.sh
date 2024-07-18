#!/bin/sh
#
# Script to publish a message to a TCP or AF UNIX socket using socat.
# After writing to the socket, the socket will be read from to check
# if the response contains a specific string to mark the request as
# being successful or not.
#
set -e

MESSAGE=
SOCKET=
RESPONSE_OK="CONNECTED"
RESPONSE_FAIL="STOPPING"

help() {
    cat << EOT >&2
Send a message to a TCP or AF UNIX socket and read the response to determine if it
was successful or not.

USAGE

   $0 [FLAGS] <MESSAGE>

POSITIONAL ARGS

    MESSAGE                 Message to be sent to the socket

FLAGS

  --socket <address>        TCP or Unix socket path. e.g. /run/example.sock or 127.0.0.1:4444
  --response-ok <string>    String to match against to determine that the request sent to the socket
                            was received by the component reacting to the request.
  --response-fail <string>  String to match against to determine an error. This will override any
                            existing ok response.
  --help                    Show this help


EXAMPLES

   $0 --socket /run/example.socket --response-ok CONNECTED --response-fail STOPPING "530,TST_throw_crabby_exception,127.0.0.1,22,18f7c014-8180-40e0-b272-03c9dec8f327"
   # Publish a c8y-remote-access-plugin message to a socket, and check for a successful connection

EOT
}

# Parse cli options
while [ $# -gt 0 ]; do
    case "$1" in
        --socket)
            SOCKET="$2"
            shift
            ;;
        --response-ok)
            RESPONSE_OK="$2"
            shift
            ;;
        --response-fail)
            RESPONSE_FAIL="$2"
            shift
            ;;
        --help|-h)
            help
            exit
            ;;
        --*|-*)
            ;;
        *)
            MESSAGE="$1"
            ;;
    esac
    shift
done

if [ -z "$MESSAGE" ]; then
    echo "Message is empty. You MUST provide a non-empty message" >&2
    usage
    exit 1
fi

SOCAT_PREFIX="TCP:"
if [ -e "$SOCKET" ]; then
    SOCAT_PREFIX="UNIX-CONNECT:"
fi

echo "Writing message ($MESSAGE) to socket ($SOCAT_PREFIX$SOCKET)" >&2

# Write to the socket and read the response until an expected response text is found
RESPONSE=$(
    echo "$MESSAGE" | socat - "$SOCAT_PREFIX$SOCKET" | while read -r line; do
        echo "socket recv: $line" >&2
        case "$line" in
            "$RESPONSE_OK")
                echo "Detected successful response" >&2
                echo "0"
                ;;
            "$RESPONSE_FAIL")
                echo "Detected error" >&2
                echo "1"
                ;;
        esac
    done
)

# Check if request was successful
RESPONSE=$(echo "$RESPONSE" | tr -d '\n')
if [ "$RESPONSE" = "0" ]; then
    echo "Found OK response" >&2
    exit 0
fi

# Assume the request was unsuccessful
echo "Did not receive expected response from socket. expected='$WAIT_FOR_OK_RESPONSE'" >&2
exit 1
