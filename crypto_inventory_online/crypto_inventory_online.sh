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
IMAGE_NAME="crypto-system-inventory-app"
if docker image inspect "$IMAGE_NAME" > /dev/null 2>&1; then
  echo "Docker image '$IMAGE_NAME' already exists. Skipping build."
else
  echo "Docker image '$IMAGE_NAME' not found. Building image..."
  docker build -t "$IMAGE_NAME" . 
fi

echo "Running Docker container with OPS_HOST=$HOST...."
docker run --rm --name crypto-system-inventory-container \
    -v "$(pwd)/crypto_inventory_report:/app/crypto_inventory_report" \
    -e OPS_HOST="$HOST" \
    crypto-system-inventory-app 
