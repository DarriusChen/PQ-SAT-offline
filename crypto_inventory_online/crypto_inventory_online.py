from opensearchpy import OpenSearch
import json
import pandas as pd
from ipwhois import IPWhois
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ------------------------------------------------------------------ #

# Get data from opensearch

host = os.getenv('OPS_HOST')
port = os.getenv('OPS_PORT')
auth = os.getenv('OPS_AUTH')


def get_data_from_opensearch(index_name, query):
    try:
        client = OpenSearch(
            hosts=[{
                'host': host,
                'port': port
            }],
            http_auth=auth,
            use_ssl=True,
            verify_certs=False,
            ssl_assert_hostname=False,
            ssl_show_warn=False  # Add this line to suppress warnings
        )
        # Know how many indices that match the pattern
        response_count = client.count(index=index_name, body=query)
        response = client.search(index=index_name,
                                 body=query,
                                 size=response_count['count'],
                                 _source=[
                                     'id.orig_h', 'id.orig_p', 'id.resp_h',
                                     'id.resp_p', 'version', 'cipher'
                                 ])
        return response
    except Exception as e:
        print(f"Error connecting to OpenSearch: {e}")
        return None


# ------------------------------------------------------------------ #

# Map ciphersuites with ssl data


# Read ciphersuite data from cipher_suites.json
def map_ciphersuite(ciphersuite_file, response):
    with open(ciphersuite_file, 'r') as file:
        ciphersuite_data = json.load(file)

    # Process ciphersuite data and map it
    formatted_cs = {cipher['name']: cipher for cipher in ciphersuite_data}

    data = [{
        "origin_ip": hit['_source'].get('id.orig_h'),
        "origin_port": hit['_source'].get('id.orig_p'),
        "response_ip": hit['_source'].get('id.resp_h'),
        "response_port": hit['_source'].get('id.resp_p'),
        "tls_version": hit['_source'].get('version', "null"),
        "cipher_suite": hit['_source'].get('cipher', "null")
    } for hit in response['hits']['hits']]

    # Prevent duplicate origin_ip and response_ip, and port
    unique_data = {
        frozenset((item['origin_ip'], item['response_ip'], item['origin_port'], item['response_port'])):
        item
        for item in data
    }
    data = list(unique_data.values())

    # Mapping
    for c in data:
        c['ciphersuite'] = formatted_cs.get(
            c['cipher_suite'], {}) if c['cipher_suite'] else "null"
        c.pop('cipher_suite', None)  # delete original cipher_suite field

    return data


# ------------------------------------------------------------------ #

# Add ISP information


def add_isp(data):
    ip_cache = {}
    for c in data:
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

# main function


def main():
    idx_pattern = os.getenv('IDX_PTN')
    cipher_file = os.getenv('CS_FILE')

    # Check required environment variables
    if not all([host, port, auth, idx_pattern, cipher_file]):
        raise ValueError(
            "Missing required environment variables. Please check your .env file."
        )

    query = {'query': {'match_all': {}}}
    response = get_data_from_opensearch(index_name=idx_pattern, query=query)
    if response is None:
        raise RuntimeError("Error getting data from OpenSearch")

    zeek_ssl_cipher = map_ciphersuite(ciphersuite_file=cipher_file,
                                      response=response)
    zeek_ssl_cipher = add_isp(zeek_ssl_cipher)

    # Export to excel
    df = pd.json_normalize(zeek_ssl_cipher)
    df.sort_values(by='tls_version', inplace=True)
    df.fillna(value="null", inplace=True)
    df = df.map(replace_empty)
    df.columns = [col.replace('.', '_') for col in df.columns]
    # print(df)
    df.to_excel('./crypto_inventory_report/zeek_ssl_cs.xlsx', index=False)
    print("Data exported to zeek_ssl_cs.xlsx successfully.")


# ------------------------------------------------------------------ #

if __name__ == '__main__':
    main()
