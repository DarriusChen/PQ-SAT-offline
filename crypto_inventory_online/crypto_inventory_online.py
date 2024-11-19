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
    http_compress=True
)


def scroll_search(client, index_pattern, query, scroll_time="15m", batch_size=10000):
    try:
        # Know how many indices that match the pattern
        response_count = client.count(index=index_pattern, body=query)['count']
        print(f"\nCollecting {response_count} indices from opensearch...")
        response = client.search(
            index=index_pattern,
            body=query,
            scroll=scroll_time,
            size=batch_size,
            _source=[
                "ts",
                "id.orig_h",
                "id.orig_p",
                "id.resp_h",
                "id.resp_p",
                "version",
                "cipher",
            ],
        )

        # Collect results from the initial search
        scroll_id = response["_scroll_id"]
        hits = response["hits"]["hits"]

        # Yield the first batch
        yield hits

        # Scroll through the data
        while True:
            response = client.scroll(scroll_id=scroll_id, scroll=scroll_time)
            hits = response["hits"]["hits"]
            if not hits:
                break  # Stop if no more data is returned

            yield hits  # Yield each batch as it's retrieved
            scroll_id = response[
                "_scroll_id"
            ]  # Update scroll ID for the next scroll call
        client.clear_scroll(scroll_id=scroll_id)  # Clear scroll context after processing
    except Exception as e:
        print(f"Error getting data from OpenSearch: {e}")
        return None


# ------------------------------------------------------------------ #

# Load and format ciphersuite data once, outside the function


def load_ciphersuite_data(ciphersuite_file):
    with open(ciphersuite_file, "r") as file:
        ciphersuite_data = json.load(file)
    return {cipher["name"]: cipher for cipher in ciphersuite_data}


formatted_cs = load_ciphersuite_data("cipher_suites.json")

# ------------------------------------------------------------------ #

# Map ciphersuites with ssl data


def map_ciphersuite_generator(hits):

    # Initialize an empty dictionary to store items
    batch_data = []
    # Initialize an empty dictionary to store isp info
    isp_cache = {}

    for hit in tqdm(hits,
        file=sys.stdout,
        desc="Adding ISP information & Mapping with ciphersuites data...",
        dynamic_ncols=True
        ):
        ts_seconds = datetime.fromtimestamp(hit["_source"].get("ts") / 10000)
        time_ = ts_seconds.strftime("%Y/%m/%d-%H:%M:%S")
        origin_ip = hit["_source"].get("id.orig_h")
        origin_port = hit["_source"].get("id.orig_p")
        response_ip = hit["_source"].get("id.resp_h")
        response_port = hit["_source"].get("id.resp_p")
        tls_version = hit["_source"].get("version", "null")
        cipher_suite = hit["_source"].get("cipher", "null")

        if response_ip not in isp_cache:
            isp_cache[response_ip] = add_isp_1(response_ip)
        isp_info = isp_cache[response_ip]

        data_item = {
            "time": time_,
            "origin_ip": origin_ip,
            "origin_port": origin_port,
            "response_ip": response_ip,
            "response_port": response_port,
            "tls_version": tls_version,
            "isp": isp_info.get("isp"),
            "country": isp_info.get("country"),
            "ciphersuite": formatted_cs.get(cipher_suite, "null"),
        }

        batch_data.append(data_item)

    yield batch_data


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
            "isp":isp_resp,
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

# 處理從 OpenSearch 查詢返回的唯一組合資料，並映射 ciphersuite
def fetch_unique_data(client, index_pattern, query, formatted_cs):

    # Know how many indices that match the pattern

    count_query = {
        "query": query["query"]
    }
    total_count = client.count(index=index_pattern, body=count_query)['count']
    print(f"\nCollecting {total_count} indices from opensearch...")
    # Initialize tqdm progress bar
    pbar = tqdm(file=sys.stdout, total=total_count, desc="Fetching unique data", unit="doc")

    unique_data = []
    after_key = None

    batch_count = 0

    while True:
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

        if "after_key" in response["aggregations"]["unique_combinations"]:
            after_key = response["aggregations"]["unique_combinations"]["after_key"]
        else:
            break

        batch_count += 1
        
        ps_logger.info(f"batch No.{batch_count} is executed.")

    return unique_data

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

    unique_data = fetch_unique_data(client, idx_pattern, query, formatted_cs)
    all_df = pd.json_normalize(unique_data)
    all_df.drop("cipher_suite", axis=1, inplace=True)
    all_df.fillna(value="null", inplace=True)
    all_df = all_df.map(replace_empty)
    all_df.columns = [col.replace('.', '_') for col in all_df.columns]

    # Set the name of export file
    dt1 = datetime.now().replace(tzinfo=timezone.utc)
    dt2 = dt1.astimezone(timezone(timedelta(hours=8)))  # transfer timezone to +8
    now = dt2.strftime("%Y_%m_%d_%H_%M_%S")
    output_file = "./crypto_inventory_report/inventory_report_" + now + ".xlsx"

    with pd.ExcelWriter(output_file, engine="xlsxwriter") as writer:
        # write into excel
        all_df.to_excel(writer, sheet_name="Inventory Report", index=False)

    ps_logger.info(f"Total data processed: {len(unique_data)}")
    print(f"Total data processed: {len(unique_data)}")
    print(f"Data successfully exported to {output_file}.")


# ------------------------------------------------------------------ #

if __name__ == "__main__":
    main()
