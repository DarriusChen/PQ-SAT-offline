#!/bin/bash

FILE_NAME="crypto_inventory_online.sh"
FULL_PATH="$(pwd)/$FILE_NAME"

# Ensure the executing permission of the task script
chmod +x "$FULL_PATH"

# get current unix timestamp
CURRENT_TIME=$(date +%s)

# timestamp of 8 hours later
EIGHT_HOURS_LATER=$(($CURRENT_TIME + 28800))

# transfer the timestamp to crontab format
RUN_MINUTE=$(date -d @$EIGHT_HOURS_LATER +'%M')
RUN_HOUR=$(date -d @$EIGHT_HOURS_LATER +'%H')

CRON_JOB="* */8 * * * "$FULL_PATH""

# Get the current crontab
CURRENT_CRON=$(crontab -l 2>/dev/null)

if echo "$CURRENT_CRON" | grep -q "$CRON_JOB"; then
    echo "Cron job found! No changes made."
    # delete original job
    NEW_CRON=$(echo "$CURRENT_CRON" | grep -vF "$CRON_JOB")
    # add same job
    NEW_CRON="$NEW_CRON"$'\n'"$CRON_JOB"
else
    echo "Cron job not found. Adding the job."
    # if not found, the add the task
    NEW_CRON="$CURRENT_CRON"$'\n'"$CRON_JOB"
fi

# update crontab
echo "$NEW_CRON" | crontab -

# Create or update crontab log file
touch ./cron_log.log

echo "Crontab updated successfully. The job will run first at $RUN_HOUR:$RUN_MINUTE and every 8 hours thereafter."