#!/bin/bash

set -e  # exit whenever encountering errors

# Load .env document
if [ -f .env ]; then
  source .env
  HOST="${1:-$OPS_HOST}" # utilize the first parameter of command. if not being set, then use OPS_HOST in .env
else
  echo ".env file not found!"
  exit 1
fi

# Export HOST to make it accessible to Docker Compose
# export HOST

# Check if the env variable is correctly modified from the default value
if [[ -z "$OPS_HOST" || "$HOST" == opensearch_host ]]; then
  echo "Error: OPS_HOST has not been changed from the default value: $OPS_HOST. It should be modified."
  exit 1
elif [ "$OPS_AUTH" == "username:passwords" ]; then
  echo "Error: OPS_AUTH has not been changed from the default value: $OPS_AUTH. It should be modified."
  exit 1
fi

# Build and run Docker container, and remove after finishing the task (--rm)
echo "OPS_AUTH is valid: $OPS_AUTH"
# Check if docker image exists
IMAGE_NAME="cipher-mapper-online"
if docker image inspect "$IMAGE_NAME" > /dev/null 2>&1; then
  echo "Docker image '$IMAGE_NAME' already exists. Skipping build."
else
  echo "Docker image '$IMAGE_NAME' not found. Building image..."
  docker build -t "$IMAGE_NAME" . 
fi

read -p "Enter start time (YYYY-MM-DD_HH:MM:SS): " start_time
read -p "Enter end time (YYYY-MM-DD_HH:MM:SS): " end_time

# # Export variables for Docker Compose
# export START_TIME="$start_time"
# export END_TIME="$end_time"

# logging file
if [ ! -f "./execution.log" ]; then
    touch ./execution.log
else
    echo "logging file detected. continue..."
fi

echo "Running Docker container with OPS_HOST=$HOST...."
docker run -d -it --rm --name pq-sat\
  -v "$(pwd)/crypto_inventory_report:/app/crypto_inventory_report" \
  -v "$(pwd)/execution.log:/app/execution.log" \
  -e OPS_HOST="$HOST" \
  -e START_TIME="$start_time" \
  -e END_TIME="$end_time" \
  cipher-mapper-online
# docker-compose up

# Create or update crontab log
# if [ -e "./cron_log.log" ]; then
#     # echo "Cron job executed at: $(date)" | sudo tee -a ./cron_test.log
#     echo "Cron job executed at: $(date)" | tee -a ./cron_test.log
# else
#     touch ./cron_log.log
# fi

