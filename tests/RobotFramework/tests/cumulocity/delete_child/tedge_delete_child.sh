#!/bin/bash
# Parse the smart rest message, ignore the first two field, and everything afterwards is the child ID
CHILD="${1#*,*,}"

# Check if command is wrapped with quotes, if so then remove them
if [[ "$CHILD" == \"*\" ]]; then
    CHILD="${CHILD:1:-1}"
fi

# Execute command
TEDGE=tedge

bash -c "$TEDGE device remove -d $CHILD"
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo "Command returned a non-zero exit code. code=$EXIT_CODE" >&2
fi

exit "$EXIT_CODE"