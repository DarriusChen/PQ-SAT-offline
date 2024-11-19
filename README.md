# Crypto Inventory Toolkit

The **Crypto Inventory Toolkit** is designed to extract, analyze, and report on SSL logs gathered by Zeek from two different data sources: OpenSearch and local PCAP files. This tool matches and enriches the extracted data with cipher suite information, facilitating an inventory of encryption systems. The results are automatically generated in an easily accessible `.xlsx` format.

## Overview

The project consists of two sub-applications, each tailored to a specific data source:

1. **OpenSearch Application** (crypto_inventory_online): Retrieves SSL logs directly from an OpenSearch instance.
2. **PCAP Application** (crypto_inventory_offline): Analyzes SSL logs extracted from local PCAP files.

Both applications utilize Zeek to extract log files such as `conn.log` and `ssl.log`. The relevant fields from the `ssl.log` files are then mapped to a `ciphersuites.json` file, generating a comprehensive inventory report of the encryption systems in use.

## Key Features

- **Detailed Reporting**: The output includes information on:
  - Source and destination IP addresses
  - Corresponding Internet Service Providers (ISPs)
  - TLS version used
  - Security levels of different cipher suites
- **Customizable Environment**: Users can adjust deployment methods and parameters to suit their specific environments and requirements.

## Output Format

The generated reports provide detailed insights with the following structure:

| Origin_IP        | Origin_Port | Response_IP      | Response_Port | TLS_Version | ISP                   | Country | Cipher_Suite_Name                     | Security_Level | Attribute_Hex_Code | TLS_Version | Crypto_System_Protocol_Tag | Protocol_Method                         | Weaknesses                                                                                              | Key_Exchange_Tag | Key_Exchange_Method                         | Key_Exchange Weaknesses                                                                 | Authentication_Tag | Authentication_Method                           | Authentication_Weaknesses                                                            | Encryption_Tag | Encryption_Method                                                                    | Encryption_Weaknesses                                                                   | Hash_Tag | Hash_Method | Hash_Weaknesses | Reference_Name | Reference_URL                      |
|------------------|-------------|-------------------|---------------|-------------|-----------------------|---------|--------------------------------------|----------------|---------------------|-------------|---------------------------|----------------------------------------|---------------------------------------------------------------------------------------------------------|-------------------|--------------------------------------------|-------------------------------------------------------------------------------------------------|------------------|------------------------------------------------|----------------------------------------------------------------------------------------------------|----------------|--------------------------------------------------------------------------------|---------------------------------------------------------------------------------|----------|-------------|------------------|----------------|-----------------------------------|
| 192.168.70.191    | 41312       | 185.125.188.55    | 443           | TLSv1.3    | UK-CANONICAL-20151111  | GB      | TLS_CHACHA20_POLY1305_SHA256        | Recommended     | 0x13              | TLS1.3      | Transport Layer Security   | TLS                                      | None                                                                                                    | PFS               | ECDHE                                      | None                                                                                           | None             | Anonymous                                        | None                                                                                             | AEAD          | ChaCha stream cipher and Poly1305       | None                                                                                         | AEAD      | ChaCha stream cipher and Poly1305       | None                                                                                           | RFC 8446       | [RFC 8446](https://ciphersuite.info/rfc/8446/) |
---
## Usage Instructions
### OpenSearch Application ( pq_sat_inline )

1. **Mount to the Correct Directory**: Ensure that you are in the `pq_sat_inline` directory.

2. **Configuration**:
   - Modify the environment variables in the `.env` file according to your setup:
     ```
     OPS_HOST=opensearch_host
     OPS_PORT=9200 
     OPS_AUTH=username:passwords
     CS_FILE=cipher_suites.json
     IDX_PTN=.ds-zeek_ssl*
     ```
   - Ensure to change `OPS_HOST` and `OPS_AUTH` before running the script to avoid errors.

3. **Execution**:
   - Run the script using the following command:
     ```bash
     bash crypto_inventory_online.sh
     ```
   - You can also pass the host variable directly after the command, then the OPS_HOST variable will be overwritten:
     ```bash
     bash crypto_inventory_online.sh 192.168.100.100
     ```

4. **Specify the time interval ( Enter start time / end time )**:
   - The format is: YYYY-MM-DD_hh:mm:ss
   - EX: 2024-10-10_00:00:00

### PCAP Application ( pq_sat_local )

1. **Mount to the Correct Directory**: Ensure that you are in the `crypto_inventory_offline` directory.

2. **Configuration**:
   - Set the necessary parameters for the PCAP application in the `.env` file:
     ```
     PCAP_FILE=your_pcap_file.pcap
     CS_FILE=ciphersuites.json
     ```
   - Ensure that the `PCAP_FILE` points to the correct local PCAP file you wish to analyze.

3. **Execution**:
   - Run the PCAP analysis script using the following command:
     ```bash
     bash crypto_inventory_pcap.sh
## File Structure

The project is organized as follows:
```plaintext
pq_sat_local/
├── pcap_files/
├── .env
├── Dockerfile
├── README.md
├── cipher_suites.json
├── crypto_inventory_local.py
├── crypto_inventory_local.sh
├── docker-compose.yaml
├── requirements.txt
└── zeek_analysis.sh
pq_sat_inline/
├── ISP_Database/
├────── GeoLite2-ASN.mmdb
├────── GeoLite2-City.mmdb
├── .dockerignore
├── .env
├── Dockerfile
├── README.md
├── cipher_suites.json
├── crypto_inventory_online.py
├── crypto_inventory_online.sh
└── requirements.txt