#!/bin/bash
NC='\033[0m'
SKYBLUE='\033[0;36m'

set -e  # 遇到錯誤時立即退出

# 檢查 docker-compose.yml 是否存在
if [ ! -f docker-compose.yaml ]; then
  echo "Error: docker-compose.yml file not found!"
  exit 1
fi

# 檢查 logs 及 report 資料夾是否存在
LOG_DIR="$(pwd)/output/logs"
REPORT_DIR="$(pwd)/output/crypto_inventory_report"


if [ ! -d "$LOG_DIR" ]; then
    mkdir -p "$LOG_DIR"
    chmod -R 777 "$LOG_DIR"
    echo "Created logs directory: $LOG_DIR"
fi

if [ ! -d "$REPORT_DIR" ]; then
    mkdir -p "$REPORT_DIR"
    chmod -R 777 "$REPORT_DIR"
    echo "Created report directory: $REPORT_DIR"
fi

# Load .env document
ENV_FILE="$(pwd)/.env"
if [ -f "$ENV_FILE" ]; then
    source "$ENV_FILE"
else
    echo ".env file not found! Ensure the file exists and contains valid variables."
    exit 1
fi

if [ -d "$LOG_PATH" ]; then # 檢查資料夾內是否有舊資料
    echo "$LOG_PATH"
    rm -rf "$LOG_PATH"/*
else
    echo "haha"
fi

# 啟動 Docker 服務並等待其結束 (--build 保證每次都重新構建映像； --dry-run可以看到更多build的步驟)
echo "Starting Docker services..."
docker-compose up

# 結束後自動刪除所有服務容器
echo "Removing Docker containers..."
docker-compose down

# 刪除 shared 目錄及其中的檔案
if [ -d ./shared ]; then
    echo "Deleting shared directory and its contents..."
    rm -rf ./shared
else
    echo "Shared directory does not exist."
fi

echo "All done! Congratulations!"
echo -e "${SKYBLUE} ======        Finished        ===== ${NC}"