import logging
import re

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Database error signatures (error-based detection)
# ---------------------------------------------------------------------------

DB_ERROR_PATTERNS: list[tuple[str, str]] = [
    # MySQL
    (r"you have an error in your sql syntax", "MySQL"),
    (r"warning: mysql", "MySQL"),
    (r"mysql_fetch_array\(\)", "MySQL"),
    (r"mysql_fetch_assoc\(\)", "MySQL"),
    (r"mysql_fetch_row\(\)", "MySQL"),
    (r"mysql_num_rows\(\)", "MySQL"),
    (r"mysql_query\(\)", "MySQL"),
    (r"com\.mysql\.jdbc\.exceptions", "MySQL"),
    (r"jdbc\.mysql", "MySQL"),
    (r"mysql server version for the right syntax", "MySQL"),
    (r"supplied argument is not a valid mysql", "MySQL"),
    (r"column count doesn't match value count", "MySQL"),
    (r"table '.*' doesn't exist", "MySQL"),
    (r"unknown column '.*' in 'field list'", "MySQL"),

    # MSSQL
    (r"unclosed quotation mark after the character string", "MSSQL"),
    (r"quoted string not properly terminated", "MSSQL"),
    (r"microsoft ole db provider for sql server", "MSSQL"),
    (r"odbc sql server driver", "MSSQL"),
    (r"microsoft jet database engine", "MSSQL"),
    (r"error converting data type", "MSSQL"),
    (r"80040e14", "MSSQL"),
    (r"80040e07", "MSSQL"),
    (r"mssql_query\(\)", "MSSQL"),
    (r"odbc microsoft access", "MSSQL"),
    (r"\[microsoft\]\[odbc", "MSSQL"),
    (r"incorrect syntax near", "MSSQL"),

    # Oracle
    (r"ora-\d{5}", "Oracle"),
    (r"oracle.*driver", "Oracle"),
    (r"sql command not properly ended", "Oracle"),
    (r"ora-01756", "Oracle"),
    (r"ora-00933", "Oracle"),
    (r"ora-00907", "Oracle"),
    (r"ora-00942", "Oracle"),
    (r"oracle error", "Oracle"),
    (r"oracle.*exception", "Oracle"),

    # PostgreSQL
    (r"pg_query\(\)", "PostgreSQL"),
    (r"pg_exec\(\)", "PostgreSQL"),
    (r"psql.*error", "PostgreSQL"),
    (r"postgresql.*error", "PostgreSQL"),
    (r"unterminated quoted string", "PostgreSQL"),
    (r"supplied argument is not a valid pg", "PostgreSQL"),
    (r"pg_num_rows\(\)", "PostgreSQL"),
    (r"pgsql.*query failed", "PostgreSQL"),
    (r"error:.*syntax error at or near", "PostgreSQL"),

    # SQLite
    (r"sqlite3\.operationalerror", "SQLite"),
    (r"sqlite_error", "SQLite"),
    (r"sqlite.*syntax error", "SQLite"),
    (r"sqlite_step\(\)", "SQLite"),
    (r"warning.*sqlite", "SQLite"),
    (r"unrecognized token", "SQLite"),

    # MariaDB
    (r"sql syntax.*mariadb", "MariaDB"),
    (r"mariadb.*syntax", "MariaDB"),
    (r"mariadb.*error", "MariaDB"),

    # DB2
    (r"db2 sql error", "DB2"),
    (r"cli driver.*db2", "DB2"),
    (r"com\.ibm\.db2", "DB2"),
    (r"sqlstate\[", "DB2"),

    # Generic SQL
    (r"syntax error.{0,100}sql", "Generic SQL"),
    (r"division by zero", "Generic SQL"),
    (r"pdoexception", "Generic SQL"),
    (r"invalid query", "Generic SQL"),
    (r"sql syntax error", "Generic SQL"),
    (r"query failed", "Generic SQL"),
    (r"sql error", "Generic SQL"),
    (r"database error", "Generic SQL"),
    (r"sql.*exception", "Generic SQL"),
    (r"access.*violation", "Generic SQL"),
    (r"warning.*mysql_", "Generic SQL"),
    (r"valid mysql result", "Generic SQL"),
]

# Pre-compile for performance
COMPILED_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(pattern, re.IGNORECASE), db_name)
    for pattern, db_name in DB_ERROR_PATTERNS
]

# ---------------------------------------------------------------------------
# CVSS scores & recommendations per severity
# ---------------------------------------------------------------------------

SEVERITY_META: dict[str, dict] = {
    "CRITICAL": {
        "cvss_score": 9.8,
        "recommendation": (
            "URGENT: Parameterize all database queries using prepared statements "
            "or an ORM. Never interpolate user input into SQL strings. "
            "Conduct immediate incident response — assume data may be compromised."
        ),
    },
    "HIGH": {
        "cvss_score": 7.5,
        "recommendation": (
            "Rewrite affected queries using prepared statements or parameterized queries. "
            "Apply input validation (whitelist allowable characters). "
            "Restrict database account privileges to minimum required."
        ),
    },
    "MEDIUM": {
        "cvss_score": 5.3,
        "recommendation": (
            "Use parameterized queries and an ORM layer to separate code from data. "
            "Enable a Web Application Firewall (WAF) as a secondary defense. "
            "Audit all database queries for similar patterns."
        ),
    },
    "LOW": {
        "cvss_score": 3.1,
        "recommendation": (
            "Sanitize and validate all user inputs server-side. "
            "Consider parameterized queries even for read-only operations. "
            "Review error handling — never expose raw SQL errors to users."
        ),
    },
}

# Response-size difference threshold for boolean detection (bytes)
BOOLEAN_SIZE_THRESHOLD = 50

# Marker string for union-based detection
UNION_MARKER = "SQLGUARD_UNION_MARKER_9x2k"

# Fix 11: increased from 4500ms → 4800ms to stay safely below the new
# 15s REQUEST_TIMEOUT while still reliably catching 5s time-based payloads.
# Note: when a per-target baseline response time is available, time-based
# detection uses baseline_time + TIME_OVER_BASELINE_MS instead.
TIME_THRESHOLD_MS = 4800
TIME_OVER_BASELINE_MS = 4000


class ResponseAnalyzer:
    """
    Analyses HTTP responses from PayloadInjector and decides if a parameter
    is vulnerable to SQL injection.

    Detection methods
    -----------------
    1. Error-based   : regex-match known DB error strings in the response body.
    2. Boolean-based : compare response sizes against a pre-fetched neutral baseline.
    3. Time-based    : flag response times > TIME_THRESHOLD_MS.

    Fix 5: Call set_baseline(url, parameter, size) BEFORE analyzing any results
    for that parameter. This ensures boolean comparison uses a true neutral
    response, not a previous injection response (which caused false positives).
    """

    def __init__(self):
        # Fix 5: Key: (url, parameter) → size of response with NEUTRAL input.
        # Populated via set_baseline() in tasks.py before injection starts.
        self._baseline: dict[tuple, int] = {}
        # Baseline response time in ms, used for dynamic time-based threshold.
        self._baseline_time: dict[tuple, int] = {}

    # ------------------------------------------------------------------
    # Fix 5: Public method to register a neutral baseline
    # ------------------------------------------------------------------

    def set_baseline(
        self,
        url: str,
        parameter: str,
        neutral_response_size: int,
        neutral_response_time_ms: int = 0,
    ) -> None:
        """
        Register the response size (and optionally response time) for a
        neutral (non-malicious) request.  Must be called once per
        (url, parameter) BEFORE analyze() is called for that pair,
        otherwise boolean-based detection is skipped.
        """
        self._baseline[(url, parameter)] = neutral_response_size
        if neutral_response_time_ms:
            self._baseline_time[(url, parameter)] = neutral_response_time_ms

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyze(self, result: dict) -> dict:
        """
        Analyse one injection result.

        Returns a dict with:
            is_vulnerable   : bool
            vuln_type       : str   ("Error-Based", "Boolean-Based", "Time-Based", "")
            severity        : str   ("CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "")
            cvss_score      : float
            recommendation  : str
            response_snippet: str   (first 300 chars of response body)
            db_type         : str   (detected DB engine, if any)
        """
        attack_type   = result.get("attack_type", "")
        response_text = result.get("response_text", "") or ""
        response_ms   = result.get("response_time_ms", 0) or 0
        timed_out     = result.get("timed_out", False)
        url           = result.get("url", "")
        parameter     = result.get("parameter", "")

        cache_key     = (url, parameter)
        response_size = len(response_text)

        # Run the detectors in priority order
        error_result   = self._check_error_based(response_text)
        if attack_type == "boolean_based":
            boolean_result = self._check_boolean_based(cache_key, response_size)
        else:
            boolean_result = {"detected": False, "delta": 0}
        
        # Only run time-based check if the payload sent was actually time-based.
        # This prevents connection drops/WAF blocks on other payloads from being flagged as time-based SQLi.
        if attack_type == "time_based":
            time_result = self._check_time_based(response_ms, timed_out, cache_key)
        else:
            time_result = {"detected": False}
            
        union_result   = self._check_union_based(response_text)

        # Fix 5: baseline is set externally via set_baseline() and never
        # overwritten here — removing the old self._baseline[cache_key] = response_size
        # line that was causing the baseline to drift with each injection response.

        # ----- Decide outcome -----
        if error_result["detected"]:
            severity  = "CRITICAL"
            vuln_type = "Error-Based"
            db_type   = error_result["db_type"]
            logger.info("VULN [Error-Based/%s] %s param=%s", db_type, url, parameter)

        elif union_result["detected"]:
            severity  = "HIGH"
            vuln_type = "Union-Based"
            db_type   = ""
            logger.info("VULN [Union-Based] %s param=%s", url, parameter)

        elif time_result["detected"]:
            severity  = "HIGH"
            vuln_type = "Time-Based"
            db_type   = ""
            logger.info("VULN [Time-Based] %s param=%s (%.1f s)",
                        url, parameter, response_ms / 1000)

        elif boolean_result["detected"]:
            severity  = "MEDIUM"
            vuln_type = "Boolean-Based"
            db_type   = ""
            logger.info("VULN [Boolean-Based] %s param=%s (Δsize=%s)",
                        url, parameter, boolean_result["delta"])

        else:
            return {
                "is_vulnerable": False,
                "vuln_type": "",
                "severity": "",
                "cvss_score": 0.0,
                "recommendation": "",
                "response_snippet": response_text[:300],
                "db_type": "",
            }

        meta = SEVERITY_META[severity]
        return {
            "is_vulnerable": True,
            "vuln_type": vuln_type,
            "severity": severity,
            "cvss_score": meta["cvss_score"],
            "recommendation": meta["recommendation"],
            "response_snippet": response_text[:300],
            "db_type": db_type,
        }

    # ------------------------------------------------------------------
    # Detection methods
    # ------------------------------------------------------------------

    def _check_error_based(self, response_text: str) -> dict:
        """Match known SQL error signatures in the response body."""
        for pattern, db_name in COMPILED_PATTERNS:
            if pattern.search(response_text):
                return {"detected": True, "db_type": db_name}
        return {"detected": False, "db_type": ""}

    def _check_boolean_based(self, cache_key: tuple, current_size: int) -> dict:
        """
        Compare current response size against the neutral baseline set by
        set_baseline(). A significant difference suggests the injected condition
        changed the query outcome.
        If no baseline exists for this key, detection is skipped entirely.
        """
        if cache_key not in self._baseline:
            # Fix 5: no baseline → skip rather than compare against a previous
            # injection response (which was causing false positives before)
            return {"detected": False, "delta": 0}

        delta = abs(current_size - self._baseline[cache_key])
        return {"detected": delta >= BOOLEAN_SIZE_THRESHOLD, "delta": delta}

    def analyze_boolean_pair(self, true_result: dict, false_result: dict) -> dict:
        """
        Analyse a TRUE/FALSE boolean payload pair.

        Only flags the parameter as vulnerable when BOTH conditions hold:
          1. true_result response size is SIMILAR to the baseline (delta < threshold)
          2. false_result response size DIFFERS from the baseline (delta >= threshold)

        This dramatically reduces false positives compared to checking a
        single response against the baseline.
        """
        url       = true_result.get("url", "")
        parameter = true_result.get("parameter", "")
        cache_key = (url, parameter)

        if cache_key not in self._baseline:
            return {
                "is_vulnerable": False,
                "vuln_type": "",
                "severity": "",
                "cvss_score": 0.0,
                "recommendation": "",
                "response_snippet": (true_result.get("response_text", "") or "")[:300],
                "db_type": "",
            }

        baseline_size = self._baseline[cache_key]
        true_size  = len(true_result.get("response_text", "") or "")
        false_size = len(false_result.get("response_text", "") or "")

        true_delta  = abs(true_size - baseline_size)
        false_delta = abs(false_size - baseline_size)

        # True-condition should match baseline; false-condition should differ
        detected = (true_delta < BOOLEAN_SIZE_THRESHOLD and
                    false_delta >= BOOLEAN_SIZE_THRESHOLD)

        if detected:
            logger.info(
                "VULN [Boolean-Based/Pair] %s param=%s "
                "(true_Δ=%s, false_Δ=%s)",
                url, parameter, true_delta, false_delta,
            )
            meta = SEVERITY_META["MEDIUM"]
            return {
                "is_vulnerable": True,
                "vuln_type": "Boolean-Based",
                "severity": "MEDIUM",
                "cvss_score": meta["cvss_score"],
                "recommendation": meta["recommendation"],
                "response_snippet": (true_result.get("response_text", "") or "")[:300],
                "db_type": "",
            }

        return {
            "is_vulnerable": False,
            "vuln_type": "",
            "severity": "",
            "cvss_score": 0.0,
            "recommendation": "",
            "response_snippet": (true_result.get("response_text", "") or "")[:300],
            "db_type": "",
        }

    def _check_union_based(self, response_text: str) -> dict:
        """Check if the union marker string appears in the response text."""
        detected = UNION_MARKER in response_text
        if detected:
            # Check for reflection false positives.
            # In a real Union SQLi, the database executes the query and only returns the marker value.
            # It does NOT return the SQL injection syntax like 'UNION SELECT' or 'UNION/**/SELECT'.
            # If the response contains the SQL structure of the payload, it's just input reflection (XSS/HTML reflection).
            response_lower = response_text.lower()
            if "union select" in response_lower or "union/**/select" in response_lower:
                logger.debug("Union marker detected but query syntax ('UNION SELECT') was also reflected. Flagging as false positive reflection.")
                return {"detected": False}
        return {"detected": detected}

    def _check_time_based(self, response_ms: int, timed_out: bool,
                          cache_key: tuple | None = None) -> dict:
        """Flag responses that took longer than the threshold (time-based blind).

        When a per-target baseline response time is available (set via
        set_baseline), the threshold is baseline_time + TIME_OVER_BASELINE_MS
        instead of the fixed TIME_THRESHOLD_MS.
        """
        # Dynamic threshold when baseline time is available
        if cache_key and cache_key in self._baseline_time:
            threshold = self._baseline_time[cache_key] + TIME_OVER_BASELINE_MS
        else:
            # Fix 11: TIME_THRESHOLD_MS is now 4800 instead of 4500
            threshold = TIME_THRESHOLD_MS

        detected = timed_out or (response_ms >= threshold)
        return {"detected": detected}