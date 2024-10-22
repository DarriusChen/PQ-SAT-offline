#!/bin/bash

set -e  # 遇到錯誤時立即退出

# 載入 .env 文件
if [ -f .env ]; then
  source .env
  HOST="${1:-$OPS_HOST}" # 使用命令行參數 $1，若未設置，則使用 .env 中的 OPS_HOST
else
  echo ".env file not found!"
  exit 1
fi

# 檢查變數是否符合預期條件
if [[ -z "$OPS_HOST" || "$HOST" == opensearch_host ]]; then
  echo "Error: OPS_HOST has not been changed from the default value: $OPS_HOST. It should be modified."
  exit 1
elif [ "$OPS_AUTH" == "username:passwords" ]; then
  echo "Error: OPS_AUTH has not been changed from the default value: $OPS_AUTH. It should be modified."
  exit 1
fi

# 建立並運行 Docker 容器，運行完成後自動刪除容器 (--rm)
echo "OPS_AUTH is valid: $OPS_AUTH"
# 檢查 Docker 映像是否已存在
IMAGE_NAME="crypto-system-inventory-app"
if docker image inspect "$IMAGE_NAME" > /dev/null 2>&1; then
  echo "Docker image '$IMAGE_NAME' already exists. Skipping build."
else
  echo "Docker image '$IMAGE_NAME' not found. Building image..."
  docker build -t "$IMAGE_NAME" .  # 建立 Docker 映像
fi

echo "Running Docker container with OPS_HOST=$HOST...."
docker run --rm --name crypto-system-inventory-container \
    -v "$(pwd)/crypto_inventory_report:/app/crypto_inventory_report" \
    -e OPS_HOST="$HOST" \
    crypto-system-inventory-app 
