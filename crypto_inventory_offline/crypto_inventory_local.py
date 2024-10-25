import json
import pandas as pd
from ipwhois import IPWhois
import os
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta
from tqdm import tqdm
import sys

# 載入 .env 文件
load_dotenv()

# ------------------------------------------------------------------ #


# 讀取 ssl.log 文件並轉換成 JSON 物件列表
def get_data_from_ssl_log(log_file):
    data = []
    with open(log_file, 'r') as f:
        data = [json.loads(line) for line in f]  # 每一行是一個 JSON 物件
        fields_to_extract = [
            'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'version',
            'cipher'
        ]
        filtered_data = [{
            field: item.get(field, "null")
            for field in fields_to_extract
        } for item in data]
    return filtered_data


# ------------------------------------------------------------------ #

# Map ciphersuites with ssl log


# Read ciphersuite data from cipher_suites.json
def map_ciphersuite(ciphersuite_file, ssl_data):
    with open(ciphersuite_file, 'r') as file:
        ciphersuite_data = json.load(file)

    # Process ciphersuite data and map it
    formatted_cs = {cipher['name']: cipher for cipher in ciphersuite_data}

    # Prevent duplicate origin_ip and response_ip and port
    # unique_data = {
    #     frozenset((item['id.orig_h'], item['id.resp_h'], item['id.orig_p'], item['id.resp_p'])):
    #     item
    #     for item in ssl_data
    # }
    # ssl_unique = list(unique_data.values())
    unique_data = {}

    for item in tqdm(ssl_data, file=sys.stdout, desc="Removing duplicates...", ncols=100):
        key = frozenset((item['id.orig_h'], item['id.resp_h'], item['id.orig_p'], item['id.resp_p']))
        
        # Try to get the current value in the dictionary; if it doesn't exist, it will be None
        existing_item = unique_data.get(key)
        
        # Update the dictionary if no item exists or if the new item has a non-null ciphersuite_name
        if existing_item is None or (item['cipher'] is not None and existing_item['cipher'] is None):
            unique_data[key] = item
    ssl_unique = list(unique_data.values())

    # formatted_ssl = [
    #     {
    #         "origin_ip": data.get('id.orig_h'),
    #         "origin_port": data.get('id.orig_p'),
    #         "response_ip": data.get('id.resp_h'),
    #         "response_port": data.get('id.resp_p'),
    #         "tls_version": data.get('version', "null"),
    #         "cipher_suite": data.get('cipher', "null"),
    #     }
    #     for data in tqdm(ssl_unique)
    # ]

    formatted_ssl = []
    for data in tqdm(ssl_unique, file=sys.stdout, desc="Merging ssl logs and adding ISP information...", ncols=100):
        isp_cache = add_isp_1(data.get('id.resp_p'))
        formatted_ssl.append({
            "origin_ip": data.get('id.orig_h'),
            "origin_port": data.get('id.orig_p'),
            "response_ip": data.get('id.resp_h'),
            "response_port": data.get('id.resp_p'),
            "tls_version": data.get('version', "null"),
            "cipher_suite": data.get('cipher', "null"),
            "isp": isp_cache.get('isp'),
            "country": isp_cache.get('country')
        })

    # Mapping
    for item in tqdm(formatted_ssl, file=sys.stdout, desc="Mapping with ciphersuite data...", ncols=100):
        item['ciphersuite'] = formatted_cs.get(item['cipher_suite'], "null")
        item.pop('cipher_suite', None)

    return formatted_ssl


# ------------------------------------------------------------------ #


# Add ISP information (all)
def add_isp(data):
    ip_cache = {}
    for c in tqdm(data, file=sys.stdout, desc="Enhanacing ISP information..."):
        ip = c['response_ip']
        if ip not in ip_cache:
            try:
                whois_info = IPWhois(ip).lookup_rdap()
                ip_cache[ip] = {
                    'isp': whois_info.get('network', {}).get('name'),
                    'country': whois_info.get('asn_country_code')
                }
            except Exception as e:
                print(f"Error looking up IP {ip}: {e}")
                ip_cache[ip] = {'isp': "null", 'country': "null"}

        c['isp'] = ip_cache[ip]['isp']
        c['country'] = ip_cache[ip]['country']
    return data


# Add ISP info (single)
def add_isp_1(ip):
    ip_cache = {}
    try:
        whois_info = IPWhois(ip).lookup_rdap()
        ip_cache[ip] = {
            'isp': whois_info.get('network', {}).get('name'),
            'country': whois_info.get('asn_country_code')
        }
    except Exception as e:
        # print(f"Error looking up IP {ip}: {e}")
        ip_cache[ip] = {'isp': "null", 'country': "null"}
    return ip_cache


# ------------------------------------------------------------------ #
# 遍歷資料夾，使用 os.scandir() 查找 ssl.log 文件
def find_ssl_logs(base_dir):
    for entry in os.scandir(base_dir):
        if entry.is_dir(follow_symlinks=False):
            yield from find_ssl_logs(entry.path)  # 遞歸遍歷子資料夾
        elif entry.is_file() and entry.name == 'ssl.log':
            yield entry.path  # 找到 ssl.log 文件，並返回其路徑


# ------------------------------------------------------------------ #


# Function to replace empty lists and dictionaries with 'null'
def replace_empty(val):
    if isinstance(val, list) and not val:  # Check if it's an empty list
        return "null"
    elif isinstance(val, dict) and not val:  # Check if it's an empty dict
        return "null"
    elif isinstance(val, str) and not val:
        return "null"
    return val  # Return the original value if it's not empty


# ------------------------------------------------------------------ #


# 處理單個 ssl.log 文件
def process_ssl_log_mapping(log_file, ciphersuite_file):

    # 讀取 ssl.log 文件
    data = get_data_from_ssl_log(log_file)
    if not data:
        print(f"Error reading data from {log_file}")
        return None, None

    # map ssl log with ciphersuite data
    zeek_ssl_cipher = map_ciphersuite(ciphersuite_file=ciphersuite_file,
                                      ssl_data=data)

    # 增加 ISP 資訊
    # zeek_ssl_cipher = add_isp(zeek_ssl_cipher)

    # 將結果轉換為 DataFrame，並取代空值
    df = pd.json_normalize(zeek_ssl_cipher)  # 將所有dictionary層級的值扁平化
    df.fillna(value="null", inplace=True)
    df.columns = [col.replace('.', '_') for col in df.columns]
    df = df.map(replace_empty)
    df.columns = [col.replace('.', '_') for col in df.columns]

    # 返回處理好的 DataFrame 和 log_file 名稱
    return df, os.path.basename(os.path.dirname(log_file))


# ------------------------------------------------------------------ #


# Main function
def main():
    log_dir = os.getenv('LOG_PATH')  # 資料夾的基礎路徑，包含多個子資料夾和 ssl.log
    cipher_file = os.getenv('CS_FILE')

    ssl_logs = list(find_ssl_logs(log_dir))
    print(f"Found {len(ssl_logs)} ssl.log files.")

    if not ssl_logs:
        print("No ssl.log files to process. Exiting.")
        return  # 如果沒有找到 ssl.log 文件，直接退出

    if not all([log_dir, cipher_file]):
        raise ValueError(
            "Missing required environment variables. Please check your .env file."
        )

    # 建立 ExcelWriter 來將結果寫入同一個 Excel 文件中
    dt1 = datetime.now().replace(tzinfo=timezone.utc)
    dt2 = dt1.astimezone(timezone(timedelta(hours=8)))  # 轉換時區 -> 東八區
    now = dt2.strftime("%Y_%m_%d_%H_%M_%S")
    output_file = "./crypto_inventory_report/inventory_report_" + now + '.xlsx'
    with pd.ExcelWriter(output_file, engine='xlsxwriter') as writer:
        # # 遍歷所有 ssl.log 文件
        for log_file in tqdm(ssl_logs,
                             file=sys.stdout,
                             desc="Processing SSL logs",
                             unit="file",
                             total=len(ssl_logs),
                             ncols=100):
            try:
                df, sheet_name = process_ssl_log_mapping(log_file, cipher_file)
                if df is not None:
                    df.to_excel(writer, sheet_name=sheet_name, index=False)
                    tqdm.write(f"Processing file: {log_file}")
                else:
                    raise ValueError(f"No data returned for {log_file}.")
            except Exception as e:
                print(f"Error processing {log_file}: {e}")

    print(f"Data has been processed and saved to {output_file}")


# ------------------------------------------------------------------ #

if __name__ == '__main__':
    main()
