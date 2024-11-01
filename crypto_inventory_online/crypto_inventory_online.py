from opensearchpy import OpenSearch
import json
import pandas as pd
from ipwhois import IPWhois
import os
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta
from tqdm import tqdm
import sys
from functools import lru_cache
import time

# Load environment variables from .env file
load_dotenv()

# ------------------------------------------------------------------ #

# Get data from opensearch

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
)


def scroll_search(client, index_pattern, query, scroll_time="20m", batch_size=10000):
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

    # Initialize an empty dictionary to store unique items
    unique_data = {}
    # Initialize an empty dictionary to store isp info
    isp_cache = {}

    for hit in tqdm(hits,
        file=sys.stdout,
        desc="Adding ISP information & Mapping with ciphersuites data...",
        dynamic_ncols=True
        ):
        ts_seconds = datetime.fromtimestamp(hit["_source"].get("ts") / 1000)
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

        # Prevent duplicates
        unique_key = (origin_ip, response_ip, origin_port, response_port)

        # Add data to unique dictionary if not added yet or update it if its cipher_suite field is not null but the added one is null
        if unique_key not in unique_data or (cipher_suite != "null" and unique_data[unique_key].get("cipher_suite") == "null"):
            unique_data[unique_key] = data_item
    yield unique_data.values()


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
    
    query = {
        "query": {
            "bool": {
                "must": [
                    {"match_all": {}},
                    {"range": {"ts": {"gte": start_ts, "lte": end_ts}}}
                ]
            }
        }
    }

    # Set the name of export file
    dt1 = datetime.now().replace(tzinfo=timezone.utc)
    dt2 = dt1.astimezone(timezone(timedelta(hours=8)))  # transfer timezone to +8
    now = dt2.strftime("%Y_%m_%d_%H_%M_%S")
    output_file = "./crypto_inventory_report/inventory_report_" + now + ".xlsx"

    total_records = 0
    batch_num = 0

    all_df = pd.DataFrame()

    for hits_batch in scroll_search(client, index_pattern=idx_pattern, query=query):

        # batch_data = [
        #     processed_data
        #     for processed_data in tqdm(map_ciphersuite_generator(hits_batch))
        # ]
        batch_data = list(map_ciphersuite_generator(hits_batch))

        # sort of data processing
        df = pd.json_normalize(batch_data)
        df.sort_values(by="tls_version", inplace=True)
        df.fillna(value="null", inplace=True)
        df.columns = [col.replace(".", "_") for col in df.columns]
        df = df.map(replace_empty)

        all_df = pd.concat([all_df, df], ignore_index=True)


        batch_num += 1
        total_records += len(batch_data)

    dup_df = all_df[all_df.duplicated(subset=['origin_ip', 'origin_port', 'response_ip', 'response_port'])]
    dup_df.to_csv('./crypto_inventory_report/dup.csv')

    with pd.ExcelWriter(output_file, engine="xlsxwriter") as writer:
        # write into excel
        all_df.to_excel(writer, sheet_name="Inventory Report", index=False)

    # 確認至少有一個批次被寫入
    if total_records == 0:
        raise ValueError("No data was written to the Excel file. Check your data and query.")

    print(f"Total data processed: {total_records}")
    print(f"Data successfully exported to {output_file}.")


# ------------------------------------------------------------------ #

if __name__ == "__main__":
    main()
