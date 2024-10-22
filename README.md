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
### OpenSearch Application (crypto_inventory_online)

1. **Configuration**:
   - Modify the environment variables in the `.env` file according to your setup:
     ```
     OPS_HOST=opensearch_host
     OPS_PORT=9200 
     OPS_AUTH=username:passwords
     CS_FILE=ciphersuites.json
     IDX_PTN=.ds-zeek_ssl*
     ```
   - Ensure to change `OPS_HOST` and `OPS_AUTH` before running the script to avoid errors.

2. **Execution**:
   - Run the script using the following command:
     ```bash
     bash crypto_inventory_online.sh
     ```

3. **Setting the Host IP**:
   - You can set the host IP in two ways:
     - **Option 1**: Modify the parameter in the `.env` file:
       ```
       OPS_HOST=192.168.50.123
       OPS_PORT=9200 
       ```
     - **Option 2**: Pass the host variable directly after the command:
       ```bash
       # Change the host to 192.168.70.85
       bash crypto_inventory_online.sh 192.168.70.85
       ```

### PCAP Application (crypto_inventory_offline)

1. **Configuration**:
   - Set the necessary parameters for the PCAP application in the `.env` file:
     ```
     PCAP_FILE=your_pcap_file.pcap
     CS_FILE=ciphersuites.json
     ```
   - Ensure that the `PCAP_FILE` points to the correct local PCAP file you wish to analyze.

2. **Execution**:
   - Run the PCAP analysis script using the following command:
     ```bash
     bash crypto_inventory_pcap.sh
