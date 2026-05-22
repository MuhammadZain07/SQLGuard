import logging
import re

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Database error signatures (error-based detection)
# ---------------------------------------------------------------------------

DB_ERROR_PATTERNS: list[tuple[str, str]] = [
    # (regex pattern, database name)
    (r"you have an error in your sql syntax", "MySQL"),
    (r"warning: mysql", "MySQL"),
    (r"mysql_fetch_array\(\)", "MySQL"),
    (r"unclosed quotation mark after the character string", "MSSQL"),
    (r"quoted string not properly terminated", "MSSQL"),
    (r"microsoft ole db provider for sql server", "MSSQL"),
    (r"odbc sql server driver", "MSSQL"),
    (r"syntax error.*sql", "Generic SQL"),
    (r"ora-\d{5}", "Oracle"),
    (r"oracle.*driver", "Oracle"),
    (r"pg_query\(\)", "PostgreSQL"),
    (r"psql.*error", "PostgreSQL"),
    (r"postgresql.*error", "PostgreSQL"),
    (r"sqlite3\.operationalerror", "SQLite"),
    (r"sqlite_error", "SQLite"),
    (r"sql syntax.*mariadb", "MariaDB"),
    (r"division by zero", "Generic SQL"),
    (r"supplied argument is not a valid (mysql|postgresql|oracle)", "Generic SQL"),
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

# Time threshold for time-based detection (milliseconds)
TIME_THRESHOLD_MS = 4500


class ResponseAnalyzer:
    """
    Analyses HTTP responses from PayloadInjector and decides if a parameter
    is vulnerable to SQL injection.

    Detection methods
    -----------------
    1. Error-based   : regex-match known DB error strings in the response body.
    2. Boolean-based : compare response sizes for true vs false payloads.
    3. Time-based    : flag response times > TIME_THRESHOLD_MS.

    Call analyze(result) for each dict returned by PayloadInjector.inject().
    """

    def __init__(self):
        # Cache last response size per (url, parameter) to enable boolean comparison
        self._baseline: dict[tuple, int] = {}

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
        attack_type    = result.get("attack_type", "")
        response_text  = result.get("response_text", "") or ""
        response_ms    = result.get("response_time_ms", 0) or 0
        timed_out      = result.get("timed_out", False)
        url            = result.get("url", "")
        parameter      = result.get("parameter", "")

        cache_key = (url, parameter)
        response_size = len(response_text)

        # Run the three detectors in priority order
        error_result   = self._check_error_based(response_text)
        boolean_result = self._check_boolean_based(cache_key, response_size)
        time_result    = self._check_time_based(response_ms, timed_out)

        # Update baseline cache AFTER boolean check
        self._baseline[cache_key] = response_size

        # ----- Decide outcome -----
        if error_result["detected"]:
            severity  = "CRITICAL"
            vuln_type = "Error-Based"
            db_type   = error_result["db_type"]
            logger.info("VULN [Error-Based/%s] %s param=%s", db_type, url, parameter)

        elif time_result["detected"]:
            severity  = "HIGH"
            vuln_type = "Time-Based"
            db_type   = ""
            logger.info("VULN [Time-Based] %s param=%s (%.1f s)", url, parameter,
                        response_ms / 1000)

        elif boolean_result["detected"]:
            severity  = "MEDIUM"
            vuln_type = "Boolean-Based"
            db_type   = ""
            logger.info("VULN [Boolean-Based] %s param=%s (Δsize=%s)",
                        url, parameter, boolean_result["delta"])

        else:
            # Not vulnerable
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
        Compare current response size against the cached baseline size.
        A significant difference suggests the condition changed the query outcome.
        """
        if cache_key not in self._baseline:
            return {"detected": False, "delta": 0}

        delta = abs(current_size - self._baseline[cache_key])
        detected = delta >= BOOLEAN_SIZE_THRESHOLD
        return {"detected": detected, "delta": delta}

    def _check_time_based(self, response_ms: int, timed_out: bool) -> dict:
        """Flag responses that took longer than the threshold (time-based blind)."""
        detected = timed_out or (response_ms >= TIME_THRESHOLD_MS)
        return {"detected": detected}