#!/bin/bash

# 載入 .env 文件
if [ -f .env ]; then
  source .env
  output_dir="${1:-$LOG_PATH}" # 使用命令行參數 $1，若未設置，則使用 .env 中的 OPS_HOST
else
  echo ".env file not found!"
  exit 1
fi


if [ -d "$output_dir" ]; then
    echo "log_output directory exits, continue..."
else
    mkdir "$output_dir"
fi


echo "Starting Zeek analysis..."

if [ "$(ls -A ./pcap_files)" ]; then # 確保 pcap 文件夾中有文件
    for pcap in ./pcap_files/*; do
        # 獲取文件的副檔名
        ext="${pcap##*.}"
        # Extract the base name of the pcap file without directory or extension
        # 檢查副檔名是否為 pcap 或 pcapng
        if [ "$ext" = "pcap" ] || [ "$ext" = "pcapng" ]; then
            # 提取文件名稱（不含路徑和副檔名）
            pcap_name=$(basename "$pcap")
            pcap_folder="${pcap_name%.*}"

            echo "Processing file: $pcap_name"
            mkdir -p "$output_dir/$pcap_folder"
            zeek -r "$pcap" Log::default_logdir="$output_dir/$pcap_folder" -e 'redef LogAscii::use_json=T;'
        else
            echo "Skipping unsupported file: $pcap"
        fi
    done
    echo "Zeek analysis completed."
        
    # 在共享目錄中創建 flag_file.txt
    touch ./shared/flag_file.txt
else
    echo "No PCAP files found in /pcap_files"
fi
