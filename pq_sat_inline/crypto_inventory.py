from opensearchpy import OpenSearch
import json
import pandas as pd
from ipwhois import IPWhois
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
ps_logger.setLevel(logging.DEBUG)  # 設定 Logger 等級

# FileHandler
file_handler = logging.FileHandler('./execution.log')
file_handler.setLevel(logging.DEBUG)

# Formatter
formatter = logging.Formatter('%(asctime)s - %(module)s: %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
file_handler.setFormatter(formatter)

# Add Handler to Logger
ps_logger.addHandler(file_handler)

# ------------------------------------------------------------------ #

# Get data from opensearch

# Load environment variables from .env file
load_dotenv()

host = os.getenv("OPS_HOST")
port = os.getenv("OPS_PORT")
auth = os.getenv("OPS_AUTH")

client = OpenSearch(
    hosts=[{"host": host, "port": port}],
    http_auth=auth,
    use_ssl=True,
    verify_certs=False,
    ssl_assert_hostname=False,
    ssl_show_warn=False,  # Add this line to suppress warnings
    http_compress=True,
    timeout=60,  # Increase timeout to 60 seconds
    max_retries=10,  # Allow up to 10 retries
    retry_on_timeout=True  # Enable retry on timeout
)

# ------------------------------------------------------------------ #

# Load and format ciphersuite data once, outside the function


def load_ciphersuite_data(ciphersuite_file):
    with open(ciphersuite_file, "r") as file:
        ciphersuite_data = json.load(file)
    return {cipher["name"]: cipher for cipher in ciphersuite_data}


formatted_cs = load_ciphersuite_data("cipher_suites.json")

# ------------------------------------------------------------------ #

# Add each ISP info
@lru_cache(maxsize=1000)  # Quickly go through the info of searched IP
def add_isp_1(ip):
    try:
        whois_info = IPWhois(ip).lookup_rdap()
        return {
            "isp": whois_info.get("network", {}).get("name"),
            "country": whois_info.get("asn_country_code"),
        }
    except Exception as e:
        # print(f"Error looking up IP {ip}: {e}")
        return {"isp": "null", "country": "null"}


isp_reader = Reader('./ISP_Database/GeoLite2-ASN.mmdb')
lc_reader = Reader('./ISP_Database/GeoLite2-City.mmdb')
def get_isp(ip):
    try:
        isp_resp = isp_reader.asn(ip)
        lc_resp = lc_reader.city(ip)
        return {
            "isp":isp_resp.autonomous_system_organization,
            "country": lc_resp.country.name,
            "city": lc_resp.city.name
        }
    except Exception as e:
        # print(f"Error looking up IP {ip}: {e}")
        return {
            "isp": "null", 
            "country": "null",
            "city": "null"
        }

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

# Get the input time and transfer to timestamp format
def get_timestamp_from_input(date_string):
    taiwan_timezone = timezone(timedelta(hours=8))
    return int(datetime.strptime(date_string, "%Y-%m-%d_%H:%M:%S").replace(tzinfo=taiwan_timezone).timestamp() * 1000)

# ------------------------------------------------------------------ #

def save_to_excel(writer, data, start_row):
    df = pd.json_normalize(data)
    df.drop("cipher_suite", axis=1, inplace=True)
    df.fillna(value="null", inplace=True)
    df = df.map(replace_empty)
    df.columns = [col.replace('.', '_') for col in df.columns]
    df['cipher_suite_reference_url'] = df['cipher_suite_reference_url'].astype(str)
    df.to_excel(writer, sheet_name="Inventory Report", index=False, startrow=start_row, header=start_row == 0)

# ------------------------------------------------------------------ #

# Cope with unique data from OpenSearch, then map with ciphersuite data
def fetch_unique_data(client, index_pattern, query, formatted_cs, writer):

    # Know how many indices that match the pattern
    count_query = {
        "query": query["query"]
    }
    total_count = client.count(index=index_pattern, body=count_query)['count']
    print(f"\nCollecting {total_count} indices from opensearch...")
    ps_logger.info(f"Collecting {total_count} indices from opensearch...")
    ps_logger.info(f"\nThere will be {round(total_count/5000)+1} batches. Starting process...")

    # Initialize tqdm progress bar
    pbar = tqdm(file=sys.stdout, total=total_count, desc="Fetching unique data", unit="doc")

    unique_data = []
    after_key = None
    batch_count = 0
    current_row = 0 # to specify the start row in excel

    while True:

        try: 
            if after_key:
                query["aggs"]["unique_combinations"]["composite"]["after"] = after_key

            response = client.search(index=index_pattern, body=query)
            buckets = response["aggregations"]["unique_combinations"]["buckets"]

            for bucket in buckets:

                time_ = datetime.fromtimestamp(bucket["time"]["hits"]["hits"][0]["_source"].get("ts", "null") / 1000).strftime("%Y/%m/%d-%H:%M:%S")
                origin_ip = bucket["key"]["origin_ip"]
                origin_port = bucket["key"]["origin_port"]
                response_ip = bucket["key"]["response_ip"]
                response_port = bucket["key"]["response_port"]
                # Grab tls_version and cipher field from aggregation results
                tls_version = bucket["tls_version"]["hits"]["hits"][0]["_source"].get("version", "null")
                cipher_suite = bucket["cipher_suite"]["hits"]["hits"][0]["_source"].get("cipher", "null")
                mapped_cipher_suite = formatted_cs.get(cipher_suite, "null")

                isp_info = get_isp(response_ip)

                data_item = {
                    "time": time_,
                    "origin_ip": origin_ip,
                    "origin_port": origin_port,
                    "response_ip": response_ip,
                    "response_port": response_port,
                    "isp": isp_info.get('isp'),
                    "country": isp_info.get('country'),
                    "city": isp_info.get('city'),
                    "tls_version": tls_version,
                    "cipher_suite": mapped_cipher_suite
                }
                unique_data.append(data_item)
            # Update tqdm progress bar
            pbar.update(len(buckets))


            save_to_excel(writer, unique_data, current_row)
            current_row += len(unique_data) # Update start row
            unique_data = []  # Clear space
            batch_count += 1
            ps_logger.info(f"No.{batch_count} batch has been processed")

            if "after_key" in response["aggregations"]["unique_combinations"]:
                after_key = response["aggregations"]["unique_combinations"]["after_key"]
            else:
                break

        except Exception as e:
            ps_logger.error(e)


    # Write in the remmain data
    if unique_data:
        batch_count += 1
        ps_logger.info(f"No.{batch_count} batch has been processed")
        save_to_excel(writer, unique_data, current_row)
        
    return batch_count, current_row

# ------------------------------------------------------------------ #

# main function
def main():
    idx_pattern = os.getenv("IDX_PTN")
    cipher_file = os.getenv("CS_FILE")

    start_time = os.getenv("START_TIME")
    end_time = os.getenv("END_TIME")

    # Check required environment variables
    if not all([host, port, auth, idx_pattern, cipher_file]):
        raise ValueError(
            "Missing required environment variables. Please check your .env file."
        )

    # transfer time format to timestamp
    if start_time and end_time:
        start_ts = get_timestamp_from_input(start_time)
        end_ts = get_timestamp_from_input(end_time)
    else:
        raise ValueError("Start time and end time are required.")
    
    # set the qeury conditions of OpenSearch, use composite aggregation to get each unique value
    query = {
        "size": 0,
        "query": {
            "bool": {
            "must": [
                {"range": {"ts": {"gte": start_ts, "lte": end_ts}}}
            ]
            }
        },
        "aggs": {
            "unique_combinations": {
            "composite": {
                "sources": [
                {"origin_ip": {"terms": {"field": "id.orig_h.keyword"}}},
                {"origin_port": {"terms": {"field": "id.orig_p"}}},
                {"response_ip": {"terms": {"field": "id.resp_h.keyword"}}},
                {"response_port": {"terms": {"field": "id.resp_p"}}}
                ],
                "size": 5000
            },
            "aggs": {
                "time": {"top_hits": {"size": 1, "_source": ["ts"]}},
                "tls_version": {"top_hits": {"size": 1, "_source": ["version"]}},
                "cipher_suite": {"top_hits": {"size": 1, "_source": ["cipher"]}}
            }
            }
        }
    }

    # Set the name of export file
    dt1 = datetime.now().replace(tzinfo=timezone.utc)
    dt2 = dt1.astimezone(timezone(timedelta(hours=8)))  # transfer timezone to +8
    now = dt2.strftime("%Y_%m_%d_%H_%M_%S")
    output_file = "./crypto_inventory_report/inventory_report_" + now + ".xlsx"

    with pd.ExcelWriter(output_file, engine="xlsxwriter") as writer:
        batch_count, all_rows = fetch_unique_data(client, idx_pattern, query, formatted_cs, writer)

    ps_logger.info(f"Data successfully processed. Total rows written: {all_rows} in {batch_count} batches to {output_file}.")
    print(f"Data successfully exported to {output_file}.")


# ------------------------------------------------------------------ #

if __name__ == "__main__":
    main()
