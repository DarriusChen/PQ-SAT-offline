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
idx_pattern = os.getenv("IDX_PTN")

cipher_file = os.getenv("CS_FILE")

start_time = os.getenv("START_TIME")
end_time = os.getenv("END_TIME")

isp_reader = Reader(os.getenv('ISP_ASN'))
lc_reader = Reader(os.getenv('ISP_CITY'))

# ------------------------------------------------------------------ #

# Set OpenSearch client

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
    """
    Load cipher suite data from a JSON file.

    :param ciphersuite_file: Path to the JSON file containing cipher suite data
    :return: Dictionary mapping cipher names to their details
    """
    with open(ciphersuite_file, "r") as file:
        ciphersuite_data = json.load(file)
    return {cipher["name"]: cipher for cipher in ciphersuite_data}


formatted_cs = load_ciphersuite_data("cipher_suites.json")

# ------------------------------------------------------------------ #

# Add each ISP info

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
        # print(f"Error looking up IP {ip}: {e}")
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

def save_to_csv(file_path, data, write_header):
    """
    Write data into a CSV file.

    :param file_path: Path to the CSV file
    :param data: List of dictionaries to write as rows
    :param write_header: Boolean indicating if the header row should be written
    """
    try:
        df = pd.json_normalize(data)
        df.drop("cipher_suite", axis=1, inplace=True)
        df.fillna(value="null", inplace=True)
        df = df.map(replace_empty)
        df.columns = [col.replace('.', '_') for col in df.columns]
        if 'cipher_suite_reference_url' in df.columns:  # ensure field exists
            df['cipher_suite_reference_url'] = df['cipher_suite_reference_url'].astype(str)
        df.to_csv(file_path, mode="a", header=write_header, index=False, encoding='utf-8')
    except Exception as e:
        error_file = f"./error_{int(time.time())}.json"
        with open(error_file, 'w') as f:
            json.dump(data, f)
        ps_logger.error(f"Error saving to CSV. Data saved to {error_file}: {e}")

# ------------------------------------------------------------------ #

def get_total_count(client, index_pattern, query):
    """
    Get the total count of documents matching the query in OpenSearch.

    :param client: OpenSearch client
    :param index_pattern: Index pattern to match
    :param query: Query conditions to apply
    :return: Total count of documents
    """
    count_query = {"query": query["query"]}
    total_count = client.count(index=index_pattern, body=count_query)['count']
    return total_count

# ------------------------------------------------------------------ #

def fetch_data_from_opensearch(client, index_pattern, query, after_key):
    """
    Fetch data from OpenSearch using the given query and after_key.

    :param client: OpenSearch client
    :param index_pattern: Index pattern to match
    :param query: Query conditions to apply
    :param after_key: Pagination key for composite aggregation
    :return: Response from OpenSearch
    """
    if after_key:
        query["aggs"]["unique_combinations"]["composite"]["after"] = after_key
    for attempt in range(3):  # retry 3 times
        try:
            return client.search(index=index_pattern, body=query)
        except Exception as e:
            ps_logger.error(f"OpenSearch query failed (attempt {attempt + 1}): {e}")
            if attempt == 2:  # stop at 3th retry
                raise RuntimeError("OpenSearch query failed after 3 attempts.")
            time.sleep(5)  # avoid instantaneous retry
# ------------------------------------------------------------------ #

def process_buckets(buckets, formatted_cs):
    """
    Process buckets from OpenSearch response and map cipher suite data.

    :param buckets: List of buckets from OpenSearch response
    :param formatted_cs: Dictionary of formatted cipher suite data
    :return: List of processed data items
    """
    isp_cache = {}  # temp storage for isp retrieval
    processed_data = []
    for bucket in buckets:
        try:
            time_ = datetime.fromtimestamp(bucket["time"]["hits"]["hits"][0]["_source"].get("ts", "null") / 1000).strftime("%Y/%m/%d-%H:%M:%S")
            origin_ip = bucket["key"]["origin_ip"]
            origin_port = bucket["key"]["origin_port"]
            response_ip = bucket["key"]["response_ip"]
            response_port = bucket["key"]["response_port"]
            tls_version = bucket["tls_version"]["hits"]["hits"][0]["_source"].get("version", "null")
            cipher_suite = bucket["cipher_suite"]["hits"]["hits"][0]["_source"].get("cipher", "null")
            mapped_cipher_suite = formatted_cs.get(cipher_suite, "null")
            isp_info = get_isp(response_ip)

            # ISP temp storage
            if response_ip not in isp_cache:
                isp_cache[response_ip] = get_isp(response_ip)
            isp_info = isp_cache[response_ip]


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
            processed_data.append(data_item)
        except KeyError as e:
            ps_logger.error(f"KeyError processing bucket: {bucket}, error: {e}")
        except Exception as e:
            ps_logger.error(f"Unexpected error processing bucket: {bucket}, error: {e}")

    return processed_data

# ------------------------------------------------------------------ #

# Cope with unique data from OpenSearch, then map with ciphersuite data
def fetch_unique_data(client, index_pattern, query, formatted_cs, csv_file):
    """
    Fetch data from OpenSearch and write it to a CSV file in batches.

    :param client: OpenSearch client
    :param index_pattern: Index pattern to match
    :param query: Query conditions to apply
    :param formatted_cs: Dictionary of formatted cipher suite data
    :param csv_file: Path to the output CSV file
    :return: Tuple containing the number of batches processed and the total number of rows written
    """
    if not all([isp_reader, lc_reader]):
        raise ValueError(
            "Missing required environment variables. Please check your .env file."
        )
    
    count_query = {
        "query": query["query"]
    }
    total_count = client.count(index=index_pattern, body=count_query)['count']
    print(f"\nCollecting {total_count} indices from opensearch...")
    ps_logger.info(f"Collecting {total_count} indices from opensearch...")
    ps_logger.info(f"There will be at most {round(total_count/5000)+1} batches. Starting process...")

    # Initialize tqdm progress bar
    pbar = tqdm(file=sys.stdout, total=total_count, desc="Fetching unique data", unit="doc")

    after_key = None
    batch_count = 0
    data_count = 0
    write_header = True  # Only write header while writing in the first batch

    while True:
        try: 
            response = fetch_data_from_opensearch(client, index_pattern, query, after_key)
            buckets = response["aggregations"]["unique_combinations"]["buckets"]

            batch_data = process_buckets(buckets, formatted_cs)

            save_to_csv(csv_file, batch_data, write_header)
            write_header = False
            data_count += len(batch_data)
            pbar.update(len(buckets))
            batch_count += 1
            ps_logger.info(f"No.{batch_count} batch has been processed")

            after_key = response["aggregations"]["unique_combinations"].get("after_key")
            if not after_key:
                break

        except Exception as e:
            ps_logger.error(f"Unexpected error in main loop: {e}")
            break

    pbar.close()
    ps_logger.info(f"Total batches: {batch_count}, Total rows: {data_count}")
    
    return batch_count, data_count

# ------------------------------------------------------------------ #

# main function
def main():
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
        "sort": [
        {"ts": {"order": "asc"}}  # sort by timestamp
        ],
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
    output_file = "./crypto_inventory_report/inventory_report_" + now + ".csv"

    batch_count, all_data_count = fetch_unique_data(client, idx_pattern, query, formatted_cs, output_file)

    ps_logger.info(f"Data successfully processed. Total rows written: {all_data_count} in {batch_count} batches to {output_file}.")
    print(f"Data successfully exported to {output_file}.")


# ------------------------------------------------------------------ #

if __name__ == "__main__":
    main()
