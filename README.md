# PQ-SAT: Inline version

**PQ-SAT** (Post-Quantum Security Assessment Tool ) is an automated solution for extracting, analyzing, and reporting on SSL logs, enriched with cryptographic data to provide actionable insights.

## Overview
**PQ-SAT Offline** leverages [Zeek](https://zeek.org/) to extract SSL logs from pcap files, then maps the extracted data with cipher suite information to generate a comprehensive inventory of cryptographic systems. This facilitates compliance audits, security assessments, and vulnerability analysis. The results are automatically output in a user-friendly `.csv` format for easy access and further analysis.

## Key Features

- **Detailed Reporting**: The [output](#output-format) includes information on:
  - Source and destination IP addresses
  - Corresponding Internet Service Providers (ISPs)
  - TLS version used
  - Related cipher suite information
- **Customizable Environment**: Users can adjust deployment methods and parameters to suit their specific environments and requirements.

## Prerequisites

Before deploying or running the application, ensure the following requirements are met:

1. **[Docker](https://www.docker.com/)**:
   - Install Docker and ensure it is running on your system.
   - [Docker Installation Guide](https://docs.docker.com/get-docker/)

2. **[MaxMind](https://dev.maxmind.com/geoip/) GeoLite2 Databases**:
   - Download the GeoLite2 ASN and City databases from [MaxMind](https://www.maxmind.com/en/accounts/1035412/geoip/downloads) (please note that you have to sign up for an account to gain access to the database) and place them in the `ISP_Database` directory:
     - `GeoLite2-ASN.mmdb`
     - `GeoLite2-City.mmdb`

3. **System Permissions**:
   - The user running the commands must have root or sudo privileges.

## Usage Instructions

1. **Mount to the Correct Directory**: Ensure that you are in the root directory of this project.

2. **Configuration**:

    Before running the script, ensure the `.env` file is correctly configured according to your environment:

    #### ***`.env` File Configuration***
    

   | **Variable** | **Description**                                              | **Default**                       | **Required** |           |
   |--------------|--------------------------------------------------------------|-----------------------------------|--------------|----------------------|
   | `LOG_PATH`   | Output path of logs extracted by zeek                      | `./log_output`      | Yes❗          |                  |
   | `CS_FILE`   | File path of ciphersuite data                                    | `./data/cipher_suites.json`                            | Yes❗           | 
   | `ISP_ASN`   | File path of ISP database (ASN)  | `./data/ISP_Database/GeoLite2-ASN.mmdb`                  | Yes❗          |
   | `ISP_CITY`    | File path of ISP database (city nad country)                              | `./data/ISP_Database/GeoLite2-City.mmdb`                   | Yes❗           |

3. **Deployment and Execution**
    - ####  Prerequisites:
        - Ensure Docker is installed and running.
        - The user running the commands must have root or sudo privileges.
    - #### Run the Service (under the project's root directory):
      ```bash
      sudo bash crypto_inventory.sh
      ```
4. Once the execution is done, go into the `crypto_inventory_report/` folder under the `output` directory, then you can see your report.

## File Structure

The project is organized as follows:
```plaintext
pq-sat-offline/
├── README.md
├── README_all.md
├── crypto_inventory.py
├── crypto_inventory.sh
├── data/
│   ├── ISP_Database/
│   │   ├── GeoLite2-ASN.mmdb
│   │   └── GeoLite2-City.mmdb
│   └── cipher_suites.json
├── Dockerfile
├── docker-compose.yaml
├── log_output/
│   ├── 2024-10-18_22-41/ (example)
│   │   ├── analyzer.log
│   │   ├── conn.log
│   │   ├── dns.log
│   │   ├── dpd.log
│   │   ├── files.log
│   │   ├── http.log
│   │   ├── ntp.log
│   │   ├── ocsp.log
│   │   ├── packet_filter.log
│   │   ├── quic.log
│   │   ├── sip.log
│   │   ├── snmp.log
│   │   ├── ssh.log
│   │   ├── ssl.log
│   │   ├── weird.log
│   │   └── x509.log
│   └── 2024-10-18_23-41/ (example)
├── output
│   ├── crypto_inventory_report
│   │   ├── inventory_report_1.csv (example)
│   │   └── inventory_report_2.csv (example)
│   └── logs
│       ├── error_1json (example)
│       ├── error_2.json (example)
│       └── execution.log
├── pcap_files
│   ├── 2024-10-18_22-41.pcap (example)
│   └── 2024-10-18_23-41.pcap (example)
├── requirements.txt
└── zeek_analysis.sh
```

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
### Data Description

- **time**: The timestamp of the connection (e.g., `2024/10/12-04:44:35`).
- **origin_ip**: The IP address of the origin host (e.g., `192.168.126.105`).
- **origin_port**: The port used by the origin host (e.g., `42970`).
- **response_ip**: The IP address of the response host (e.g., `23.200.152.77`).
- **response_port**: The port used by the response host (e.g., `443`).
- **isp**: The Internet Service Provider of the response IP (e.g., `Akamai International B.V.`).
- **country**: The country where the response IP is located (e.g., `United States`).
- **city**: The city where the response IP is located (e.g., `Hong Kong`).
- **tls_version**: The TLS version used in the connection (e.g., `TLSv12` or `TLSv13`).
- **cipher_suite_name**: The name of the cipher suite used (e.g., `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`).
- **cipher_suite_security**: The security level of the cipher suite (e.g., `secure` or `recommended`).
- **cipher_suite_attribute_hex_code**: The hex code attributes of the cipher suite (e.g., `['0xC0', '0x30']`).
- **cipher_suite_attribute_tls_version**: The TLS versions supported by the cipher suite (e.g., `['TLS1.2', 'TLS1.3']`).
- **cipher_suite_crypyto_system_protocol_tag**: The cryptographic protocol tag (e.g., `Transport Layer Security (TLS)`).
- **cipher_suite_crypyto_system_protocol_method**: The method used by the cryptographic protocol (e.g., `RSA Authentication`).
- **cipher_suite_crypyto_system_protocol_weakness**: Known weaknesses of the cryptographic protocol (e.g., `Reports of performance issues for keys longer than 3072-bit`).
- **cipher_suite_crypyto_system_keyxchange_tag**: The key exchange algorithm tag (e.g., `PFS`).
- **cipher_suite_crypyto_system_keyxchange_method**: The method used for key exchange (e.g., `Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)`).
- **cipher_suite_crypyto_system_keyxchange_weakness**: Weaknesses in the key exchange method (e.g., `Non-ephemeral Key Exchange` or `Raccoon Attack`).
- **cipher_suite_crypyto_system_authentication_tag**: The authentication algorithm tag (e.g., `null` or `RSA`).
- **cipher_suite_crypyto_system_authentication_method**: The method used for authentication (e.g., `Rivest Shamir Adleman algorithm (RSA)`).
- **cipher_suite_crypyto_system_authentication_weakness**: Weaknesses in the authentication method (e.g., `Reports of performance issues for RSA keys longer than 3072-bit`).
- **cipher_suite_crypyto_system_encryption_tag**: The encryption algorithm tag (e.g., `AEAD`).
- **cipher_suite_crypyto_system_encryption_method**: The method used for encryption (e.g., `Advanced Encryption Standard with 256-bit key in Galois/Counter mode (AES 256 GCM)`).
- **cipher_suite_crypyto_system_encryption_weakness**: Weaknesses in the encryption method (e.g., `Cipher Block Chaining` or `Data Encryption Standard`).
- **cipher_suite_crypyto_system_hash_tag**: The hashing algorithm tag (e.g., `AEAD`).
- **cipher_suite_crypyto_system_hash_method**: The method used for hashing (e.g., `Advanced Encryption Standard with 256-bit key in Galois/Counter mode (AES 256 GCM)`).
- **cipher_suite_crypyto_system_hash_weakness**: Weaknesses in the hashing method (e.g., `Secure Hash Algorithm 1: The Secure Hash Algorithm 1 has been proven to be insecure as of 2017 (see shattered.io).`).
- **cipher_suite_reference_name**: The reference name for the cipher suite (e.g., `RFC 5289`).
- **cipher_suite_reference_url**: The reference URL for the cipher suite (e.g., `[RFC 5289](https://ciphersuite.info/rfc/5289/)`).
---