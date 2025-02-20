import json
import pandas as pd
from geoip2.database import Reader
import os
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta
from tqdm import tqdm
import sys
from functools import lru_cache
import time
import logging

# ------------------------------------------------------------------ #

# Set logging config with isolate logger

# Logger
ps_logger = logging.getLogger('pqsat-execution')
ps_logger.setLevel(logging.DEBUG)

# FileHandler
file_handler = logging.FileHandler('./output/logs/execution.log')
file_handler.setLevel(logging.DEBUG)

# Formatter
class TaiwanFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        utc_dt = datetime.fromtimestamp(record.created)
        taiwan_dt = utc_dt + timedelta(hours=8)  # UTC+8 
        if datefmt:
            return taiwan_dt.strftime(datefmt)
        return taiwan_dt.isoformat()
    
formatter = TaiwanFormatter('%(asctime)s - %(module)s: %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
file_handler.setFormatter(formatter)

# Add Handler to Logger
ps_logger.addHandler(file_handler)

# ------------------------------------------------------------------ #

# Load environment variables from .env file
load_dotenv()

log_dir = os.getenv('LOG_PATH')  # 資料夾的基礎路徑，包含多個子資料夾和 ssl.log
cipher_file = os.getenv('CS_FILE')

ip_filter_file = os.getenv("IP_FILTER_FILE")

isp_reader = Reader(os.getenv('ISP_ASN'))
lc_reader = Reader(os.getenv('ISP_CITY'))

# ------------------------------------------------------------------ #

# 遍歷資料夾，使用 os.scandir() 查找 ssl.log 文件
def find_ssl_logs(base_dir):
    for entry in os.scandir(base_dir):
        if entry.is_dir(follow_symlinks=False):
            yield from find_ssl_logs(entry.path)  # 遞歸遍歷子資料夾
        elif entry.is_file() and entry.name == 'ssl.log':
            yield entry.path  # 找到 ssl.log 文件，並返回其路徑

# 讀取 ssl.log 文件並轉換成 JSON 物件列表
def get_data_from_ssl_log(log_file):
    data = []
    with open(log_file, 'r') as f:
        data = [json.loads(line) for line in f]  # 每一行是一個 JSON 物件
        fields_to_extract = [
            'ts', 'id.orig_h', 'id.resp_h', 'id.resp_p',
            'version', 'cipher', 'ssl_history'
        ]
        filtered_data = [{
            field: item.get(field, "null")
            for field in fields_to_extract
        } for item in data]
    return filtered_data

# ------------------------------------------------------------------ #

# Load and format ciphersuite data once, outside the function


def load_ciphersuite_data(ciphersuite_file):
    """
    Load cipher suite data from a JSON file.

    :param ciphersuite_file: Path to the JSON file containing cipher suite data
    :return: Dictionary mapping cipher names to their details
    """
    with open(ciphersuite_file, "r") as file:
        ciphersuite_data = json.load(file)
    return {cipher["name"]: cipher for cipher in ciphersuite_data}

# ------------------------------------------------------------------ #

# Add each ISP info

@lru_cache(maxsize=1000)
def get_isp(ip):
    """
    Fetch ISP, country, and city information for a given IP address using MaxMind databases.

    :param ip: IP address to lookup
    :return: Dictionary containing ISP, country, and city details
    """
    try:
        isp_resp = isp_reader.asn(ip)
        lc_resp = lc_reader.city(ip)
        return {
            "isp":isp_resp.autonomous_system_organization,
            "country": lc_resp.country.name,
            "city": lc_resp.city.name
        }
    except Exception as e:
        return {
            "isp": "null", 
            "country": "null",
            "city": "null"
        }

# ------------------------------------------------------------------ #


# Function to replace empty lists and dictionaries with 'null'

def replace_empty(val):
    """
    Replace empty lists, dictionaries, or strings with 'null'.

    :param val: Value to check and possibly replace
    :return: Original value or 'null' if empty
    """
    if isinstance(val, list) and not val:  # Check if it's an empty list
        return "null"
    elif isinstance(val, dict) and not val:  # Check if it's an empty dict
        return "null"
    elif isinstance(val, str) and not val:
        return "null"
    return val  # Return the original value if it's not empty

# ------------------------------------------------------------------ #

# Get the input time and transfer to timestamp format

def get_timestamp_from_input(date_string):
    """
    Convert a date string in 'YYYY-MM-DD_HH:MM:SS' format to a UTC timestamp in milliseconds.

    :param date_string: Date string to convert
    :return: Timestamp in milliseconds
    """
    taiwan_timezone = timezone(timedelta(hours=8))
    return int(datetime.strptime(date_string, "%Y-%m-%d_%H:%M:%S").replace(tzinfo=taiwan_timezone).timestamp() * 1000)

# ------------------------------------------------------------------ #

taiwan_timezone = timezone(timedelta(hours=8))

def map_ciphersuite(ssl_data, formatted_cs):
    """
    Process analyzed ssl data and map with cipher suite data.

    :param ssl_data: List of analyzed ssl data
    :param formatted_cs: Dictionary of formatted cipher suite data
    :return: List of processed data items
    """
    isp_cache = {}  # temp storage for isp retrieval
    processed_data = []
    for data in ssl_data:
        try:
            time_ = datetime.fromtimestamp(data.get("ts", "null"), tz=timezone.utc).astimezone(taiwan_timezone).strftime("%Y/%m/%d-%H:%M:%S")
            origin_ip = data.get('id.orig_h')
            response_ip = data.get('id.resp_h')
            response_port = data.get('id.resp_p')
            tls_version = data.get('version', "null")
            cipher_suite = data.get('cipher', "null")
            mapped_cipher_suite = formatted_cs.get(cipher_suite, "null")
            isp_info = get_isp(response_ip)
            ssl_history = data.get('ssl_history', 'null')

            # ISP temp storage
            if response_ip not in isp_cache:
                isp_cache[response_ip] = get_isp(response_ip)
            isp_info = isp_cache[response_ip]

            if 's' in ssl_history or 'j' in ssl_history:
                data_item = {
                    "time": time_,
                    "origin_ip": origin_ip,
                    "response_ip": response_ip,
                    "response_port": response_port,
                    "isp": isp_info.get('isp'),
                    "country": isp_info.get('country'),
                    "city": isp_info.get('city'),
                    "tls_version": tls_version,
                    "cipher_suite": mapped_cipher_suite
                }
                processed_data.append(data_item)
            else:
                continue

        except KeyError as e:
            ps_logger.error(f"KeyError processing bucket: {data}, error: {e}")
        except Exception as e:
            ps_logger.error(f"Unexpected error processing bucket: {data}, error: {e}")

    return processed_data

# ------------------------------------------------------------------ #

# 處理單個 ssl.log 文件
def process_ssl_log_mapping(log_file):

    formatted_cs = load_ciphersuite_data(cipher_file)

    # 讀取 ssl.log 文件
    ssl_data = get_data_from_ssl_log(log_file)
    if not ssl_data:
        print(f"Error reading data from {log_file}")
        return None, None
    print(f"\nProcessing file: {log_file}")

    # map ssl log with ciphersuite data
    zeek_ssl_cipher = map_ciphersuite(ssl_data=ssl_data,
                                      formatted_cs=formatted_cs
                                      )

    # 增加 ISP 資訊
    # zeek_ssl_cipher = add_isp(zeek_ssl_cipher)

    # 將結果轉換為 DataFrame，並取代空值
    try:
        df = pd.json_normalize(zeek_ssl_cipher)  # 將所有dictionary層級的值扁平化
        if 'cipher_suite' in df.columns:
            df.drop("cipher_suite", axis=1, inplace=True)
        df.fillna(value="null", inplace=True)
        df = df.map(replace_empty)
        df.columns = [col.replace('.', '_') for col in df.columns]
        # Drop all duplicate pairs in DataFrame
        df.drop_duplicates(subset = ["origin_ip", "response_ip", "response_port"], inplace=True)
    except Exception as e:
        error_file = f"./logs/error_{int(time.time())}.json"
        with open(error_file, 'w') as f:
            json.dump(zeek_ssl_cipher, f)
        ps_logger.error(f"Error processing ssl log mapping. Data saved to {error_file}: {e}")

    # 返回處理好的 DataFrame 和 log_file 名稱
    return df, os.path.basename(os.path.dirname(log_file))

# ------------------------------------------------------------------ #

# main function
def main():

    ssl_log_paths = list(find_ssl_logs(log_dir))
    print(f"Found {len(ssl_log_paths)} ssl.log files.")

    if not ssl_log_paths:
        print("No ssl.log files to rpocess. Exiting.")
        return  # 如果沒有找到 ssl.log 文件，直接退出

    if not all([log_dir, cipher_file]):
        raise ValueError(
            "Missing required environment variables. Please check your .env file."
        )

    combined_df = pd.DataFrame()

    # 遍歷所有 ssl.log 文件，並進行增量合併
    for log_file in tqdm(ssl_log_paths,
                         file=sys.stdout,
                         desc="Processing SSL logs",
                         unit="file",
                         total=len(ssl_log_paths),
                         ncols=100):
        try:
            df, _ = process_ssl_log_mapping(log_file)
            if df is not None:
                # 逐步合併
                combined_df = pd.concat([combined_df, df], ignore_index=True)
            else:
                raise ValueError(f"No data returned for {log_file}.")
        except Exception as e:
            print(f"Error processing {log_file}: {e}")

    # Set the name of export file
    dt1 = datetime.now().replace(tzinfo=timezone.utc)
    dt2 = dt1.astimezone(timezone(timedelta(hours=8)))  # transfer timezone to +8
    now = dt2.strftime("%Y_%m_%d_%H_%M_%S")
    output_file = "./output/crypto_inventory_report/inventory_report_" + now + ".csv"

    combined_df.to_csv(output_file, mode="w", index=False, encoding='utf-8')

    files_count, all_data_count = len(ssl_log_paths), combined_df.shape[0]
    
    ps_logger.info(f"Data successfully processed. Total rows written: {all_data_count} in {files_count} files to {output_file}.")
    print(f"Data successfully exported to {output_file}.")

# ------------------------------------------------------------------ #

if __name__ == "__main__":
    main()
