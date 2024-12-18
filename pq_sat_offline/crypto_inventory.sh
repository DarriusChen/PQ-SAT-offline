#!/bin/bash

set -e  # 遇到錯誤時立即退出

# 檢查 docker-compose.yml 是否存在
if [ ! -f docker-compose.yaml ]; then
  echo "Error: docker-compose.yml file not found!"
  exit 1
fi

# 檢查 logs 及 report 資料夾是否存在
LOG_DIR="$(pwd)/logs"
REPORT_DIR="$(pwd)/crypto_inventory_report"

if [ ! -d "$LOG_DIR" ]; then
    mkdir -p "$LOG_DIR"
    echo "Created logs directory: $LOG_DIR"
fi

if [ ! -d "$REPORT_DIR" ]; then
    mkdir -p "$REPORT_DIR"
    echo "Created report directory: $REPORT_DIR"
fi

# 進度條函數，動態根據實際時間顯示
progress_bar_dynamic() {
    local start_time=$1
    local elapsed=0
    local total_time=$2

    while [ $elapsed -lt $total_time ]; do
        bar_length=$((elapsed * 20 / total_time))  # 假設進度條有20格
        remaining_length=$((20 - bar_length))
        bar=$(printf "%${bar_length}s" | tr " " "█")
        empty=$(printf "%${remaining_length}s")
        percentage=$((elapsed * 100 / total_time))
        printf "\rProgress: [%s%s] %d%%" "$bar" "$empty" "$percentage"
        sleep 1
        elapsed=$(( $(date +%s) - $start_time ))
    done
    printf "\rProgress: [████████████████████] 100%%\n"  # 結束後顯示完整進度條
}

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