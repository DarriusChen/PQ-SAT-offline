#!/bin/bash
NC='\033[0m'
SKYBLUE='\033[0;36m'
RED='\033[1;31m'

set -e  # 遇到錯誤時立即退出

# 檢查 logs 及 report 資料夾是否存在
LOG_DIR="$(pwd)/output/logs"
REPORT_DIR="$(pwd)/output/crypto_inventory_report"

check_files() {
  # 檢查 docker-compose.yml 是否存在
  if [ ! -f docker-compose.yaml ]; then
    echo -e "${RED}Error: docker-compose.yml file not found! ${NC}"
    exit 1
  fi

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
      echo -e "${RED}Error: .env file not found! Ensure the file exists and contains valid variables. ${NC}"
      exit 1
  fi

  if [ -d "$LOG_PATH" ]; then # 檢查zeek log資料夾內是否有舊資料
      echo "$LOG_PATH"
      rm -rf "$LOG_PATH"/*
  else
      echo "haha"
  fi
}

# 啟動 Docker 服務並等待其結束 (--build 保證每次都重新構建映像； --dry-run可以看到更多build的步驟)
run_service() {
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
      echo -e "${RED}Shared directory does not exist. ${NC}"
  fi

}

# ---------------------------------------------------------------------------------------#
# Certificate validation

CERT_FILE="./cert/certificate.crt"

if [ ! -f "$CERT_FILE" ]; then
    echo -e "${RED}Error: Certificate not found! ${NC}"
    exit 1
fi


# 取得憑證過期日期（轉換為 Unix Timestamp）
EXPIRY_DATE=$(openssl x509 -enddate -noout -in "$CERT_FILE" | cut -d= -f2)

# 判斷作業系統並進行相應處理
if [[ "$(uname)" == "Darwin" ]]; then
    # macOS (BSD date)
    
    # 移除 GMT 和月份
    EXPIRY_DATE_CLEANED=$(echo "$EXPIRY_DATE" | sed 's/ GMT//;s/[A-Za-z]* //')
    
    # 直接使用簡單的日期格式
    EXPIRY_TIMESTAMP=$(date -j -f "%d %H:%M:%S %Y" "$EXPIRY_DATE_CLEANED" "+%s")
else
    # Linux (GNU date)
    EXPIRY_TIMESTAMP=$(date -d "$EXPIRY_DATE" "+%s")
fi

# 驗證轉換結果
if [[ $? -ne 0 ]]; then
    echo -e "${RED}Error：無法轉換憑證日期 ${NC}"
    exit 1
fi

# 取得當前時間戳記
CURRENT_TIMESTAMP=$(date +%s)

# 如果憑證已過期，則禁止執行程式
if [ "$CURRENT_TIMESTAMP" -ge "$EXPIRY_TIMESTAMP" ]; then
    echo -e "${RED}Error: Certificate has expired. Execution denied! ${NC}"
    exit 1
else
    echo -e "${SKYBLUE}Certificate is valid. Running the program... ${NC}"
    check_files
    run_service
fi

echo "All done! Congratulations!"
echo -e "${SKYBLUE} ======        Finished        ===== ${NC}"