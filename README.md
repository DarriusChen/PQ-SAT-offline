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

| time                | origin_ip       | origin_port | response_ip    | response_port | isp                         | country       | city      | tls_version | cipher_suite_name                     | cipher_suite_security | cipher_suite_attribute_hex_code | cipher_suite_attribute_tls_version | cipher_suite_crypyto_system_protocol_tag | cipher_suite_crypyto_system_protocol_method | cipher_suite_crypyto_system_protocol_weakness                                                                                                                                                                                                                                          | cipher_suite_crypyto_system_keyxchange_tag | cipher_suite_crypyto_system_keyxchange_method   | cipher_suite_crypyto_system_keyxchange_weakness                                                                                                                                                                                                                                        | cipher_suite_crypyto_system_authentication_tag | cipher_suite_crypyto_system_authentication_method | cipher_suite_crypyto_system_authentication_weakness                                                                                                                                                                                                                                    | cipher_suite_crypyto_system_encryption_tag | cipher_suite_crypyto_system_encryption_method                                     | cipher_suite_crypyto_system_encryption_weakness | cipher_suite_crypyto_system_hash_tag | cipher_suite_crypyto_system_hash_method                                           | cipher_suite_crypyto_system_hash_weakness | cipher_suite_reference_name | cipher_suite_reference_url                                               |
| ------------------- | --------------- | ----------- | -------------- | ------------- | --------------------------- | ------------- | --------- | ----------- | ------------------------------------- | --------------------- | ------------------------------- | ---------------------------------- | ---------------------------------------- | ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ | ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- | ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ | --------------------------------------------------------------------------------- | ----------------------------------------------- | ------------------------------------ | --------------------------------------------------------------------------------- | ----------------------------------------- | --------------------------- | ------------------------------------------------------------------------ |
| 2024/10/12-04:44:35 | 192.168.126.105 | 42970       | 23.200.152.77  | 443           | Akamai International B.V.   | Hong Kong     | Hong Kong | TLSv12      | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | secure                | ['0xC0', '0x30']                | ['TLS1.2', 'TLS1.3']               | null                                     | Transport Layer Security (TLS)              | [['RSA Authentication', 'There are reports that servers using the RSA authentication algorithm with keys longer than 3072-bit may experience heavy performance issues leading to connection timeouts and even service unavailability if many clients open simultaneous connections.']] | PFS                                        | Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) | [['RSA Authentication', 'There are reports that servers using the RSA authentication algorithm with keys longer than 3072-bit may experience heavy performance issues leading to connection timeouts and even service unavailability if many clients open simultaneous connections.']] | null                                           | Rivest Shamir Adleman algorithm (RSA)             | [['RSA Authentication', 'There are reports that servers using the RSA authentication algorithm with keys longer than 3072-bit may experience heavy performance issues leading to connection timeouts and even service unavailability if many clients open simultaneous connections.']] | AEAD                                       | Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM) | null                                            | AEAD                                 | Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM) | null                                      | RFC 5289                    | [https://ciphersuite.info/rfc/5289/](https://ciphersuite.info/rfc/5289/) |
| 2024/10/13-21:24:42 | 192.168.126.105 | 45264       | 23.200.152.77  | 443           | Akamai International B.V.   | Hong Kong     | Hong Kong | TLSv12      | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | secure                | ['0xC0', '0x30']                | ['TLS1.2', 'TLS1.3']               | null                                     | Transport Layer Security (TLS)              | [['RSA Authentication', 'There are reports that servers using the RSA authentication algorithm with keys longer than 3072-bit may experience heavy performance issues leading to connection timeouts and even service unavailability if many clients open simultaneous connections.']] | PFS                                        | Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) | [['RSA Authentication', 'There are reports that servers using the RSA authentication algorithm with keys longer than 3072-bit may experience heavy performance issues leading to connection timeouts and even service unavailability if many clients open simultaneous connections.']] | null                                           | Rivest Shamir Adleman algorithm (RSA)             | [['RSA Authentication', 'There are reports that servers using the RSA authentication algorithm with keys longer than 3072-bit may experience heavy performance issues leading to connection timeouts and even service unavailability if many clients open simultaneous connections.']] | AEAD                                       | Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM) | null                                            | AEAD                                 | Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM) | null                                      | RFC 5289                    | [https://ciphersuite.info/rfc/5289/](https://ciphersuite.info/rfc/5289/) |
| 2024/10/18-22:06:37 | 192.168.126.105 | 58828       | 23.200.152.77  | 443           | Akamai International B.V.   | Hong Kong     | Hong Kong | TLSv12      | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | secure                | ['0xC0', '0x30']                | ['TLS1.2', 'TLS1.3']               | null                                     | Transport Layer Security (TLS)              | [['RSA Authentication', 'There are reports that servers using the RSA authentication algorithm with keys longer than 3072-bit may experience heavy performance issues leading to connection timeouts and even service unavailability if many clients open simultaneous connections.']] | PFS                                        | Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) | [['RSA Authentication', 'There are reports that servers using the RSA authentication algorithm with keys longer than 3072-bit may experience heavy performance issues leading to connection timeouts and even service unavailability if many clients open simultaneous connections.']] | null                                           | Rivest Shamir Adleman algorithm (RSA)             | [['RSA Authentication', 'There are reports that servers using the RSA authentication algorithm with keys longer than 3072-bit may experience heavy performance issues leading to connection timeouts and even service unavailability if many clients open simultaneous connections.']] | AEAD                                       | Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM) | null                                            | AEAD                                 | Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM) | null                                      | RFC 5289                    | [https://ciphersuite.info/rfc/5289/](https://ciphersuite.info/rfc/5289/) |
| 2024/10/12-15:50:21 | 192.168.126.117 | 49152       | 52.113.194.132 | 443           | MICROSOFT-CORP-MSN-AS-BLOCK | United States | null      | TLSv12      | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | secure                | ['0xC0', '0x30']                | ['TLS1.2', 'TLS1.3']               | null                                     | Transport Layer Security (TLS)              | [['RSA Authentication', 'There are reports that servers using the RSA authentication algorithm with keys longer than 3072-bit may experience heavy performance issues leading to connection timeouts and even service unavailability if many clients open simultaneous connections.']] | PFS                                        | Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) | [['RSA Authentication', 'There are reports that servers using the RSA authentication algorithm with keys longer than 3072-bit may experience heavy performance issues leading to connection timeouts and even service unavailability if many clients open simultaneous connections.']] | null                                           | Rivest Shamir Adleman algorithm (RSA)             | [['RSA Authentication', 'There are reports that servers using the RSA authentication algorithm with keys longer than 3072-bit may experience heavy performance issues leading to connection timeouts and even service unavailability if many clients open simultaneous connections.']] | AEAD                                       | Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM) | null                                            | AEAD                                 | Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM) | null                                      | RFC 5289                    | [https://ciphersuite.info/rfc/5289/](https://ciphersuite.info/rfc/5289/) |
| 2024/10/17-12:24:35 | 192.168.126.117 | 49154       | 142.251.8.95   | 443           | GOOGLE                      | United States | null      | TLSv13      | TLS_AES_128_GCM_SHA256                | recommended           | ['0x13', '0x01']                | ['TLS1.3']                         | null                                     | Transport Layer Security (TLS)              | null                                                                                                                                                                                                                                                                                   | PFS                                        | ECDHE                                           | null                                                                                                                                                                                                                                                                                   | null                                           | null                                              | null                                                                                                                                                                                                                                                                                   | AEAD                                       | Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM) | null                                            | AEAD                                 | Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM) | null                                      | RFC 8446                    | [https://ciphersuite.info/rfc/8446/](https://ciphersuite.info/rfc/8446/) |
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