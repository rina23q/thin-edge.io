#!/bin/sh

ACTION="$1"

echo ':::begin-tedge:::'

case "$ACTION" in
    "tmppath")
        TYPE="$2"
        DATEFROM="$3"
        DATETO="$4"
        FILE_NAME="$TYPE"_"$DATEFROM"_"$DATETO".log
        DIR_PATH="/tmp"
        FILE_PATH="$DIR_PATH"/"$FILE_NAME"

        echo '{"status":"prepare_log_file", "filePath":"'$FILE_PATH'"}'
        ;;

    "prepare")
        TYPE="$2"
        DATEFROM="$3"
        DATETO="$4"
        LINES="$5"
        FILE_PATH="$6"

        # SQL actions should be here. Somehow output to $FILE_PATH
        printf "This is the log of type '%s'.\n" "$TYPE" > "$FILE_PATH"
        printf "Date from '%s' to '%s' with '%d' lines.\n" "$DATEFROM" "$DATETO" "$LINES" >> "$FILE_PATH"
        echo '{"status":"upload_to_fts"}'
        ;;

    "upload")
        TEDGE_URL="$2"
        FILE_PATH="$3"

        curl -v -d @"$FILE_PATH" -X PUT "$TEDGE_URL"
        CURL_STATUS=$?

        if [ $CURL_STATUS -eq 0 ]; then
            echo '{"status":"successful"}'
        else
            echo '{"status":"failed"}'
        fi
        ;;


    *)
        echo '{"status":"failed", "reason":"unknown state"}';;
esac

echo ':::end-tedge:::'