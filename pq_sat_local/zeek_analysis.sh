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

# 啟動簡單的處理動畫
spin() {
    local FILE="$1"
    local PROCESS="$2"
    local -a sp=('|' '/' '-' '\\')

    while [ ! -f "$FILE" ]; do
        for i in "${sp[@]}"; do
            printf "\rAnalyzing %s... %s" "$PROCESS" "$i"
            sleep 0.1
        done
    done
    printf "\rProcessing $PROCESS completed!    \n"
}


if [ "$(ls -A ./pcap_files)" ]; then # 確保 pcap 文件夾中有文件
    for pcap in ./pcap_files/*.{pcap,pcapng}; do
        # Extract the base name of the pcap file without directory or extension
        pcap_name=$(basename "$pcap")
        pcap_folder="${pcap_name%.*}"

        # echo "Processing file: $pcap_name..."
        mkdir -p "$output_dir/$pcap_folder"
        zeek -C -r "$pcap" Log::default_logdir="$output_dir/$pcap_folder" -e 'redef LogAscii::use_json=T;' -b base/protocols/ssl
        echo "Analyzed $pcap_name done. Continue..." 
        done
    echo "Zeek analysis completed."
    
    # 在共享目錄中創建 flag_file.txt
    touch ./shared/flag_file.txt
else
    echo "No PCAP files found in /pcap_files"
fi
