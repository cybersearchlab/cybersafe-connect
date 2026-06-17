"""
duplicate.py
================================================================================
CVE Deduplication & State Tracking Module
================================================================================

This module is responsible for maintaining a persistent state of processed
CVEs in order to ensure incremental processing across multiple pipeline runs.

It acts as a deduplication layer inside the Cyber Threat Intelligence system,
preventing duplicate alerts, duplicate processing, and redundant reporting.

--------------------------------------------------------------------------------
WORKFLOW
--------------------------------------------------------------------------------

STEP 1 — Load Processing State
    Loads previously processed CVE identifiers from local storage.

STEP 2 — Database Query
    Retrieves CVEs from SQLite database filtered by severity and score.

STEP 3 — Deduplication Filter
    Removes CVEs already processed in previous runs.

STEP 4 — State Update
    Updates persistent storage with newly discovered CVEs.

STEP 5 — Return Intelligence Output
    Returns new CVEs + processing statistics.

--------------------------------------------------------------------------------
INPUTS
--------------------------------------------------------------------------------

Database:
    - cve_data.db

Table:
    - cves

Required fields:
    - id
    - published
    - lastModified
    - description
    - score
    - vector
    - severity

State File:
    processed_cves.json

Structure:
{
    "ids": ["CVE-XXXX-XXXX", ...],
    "last_run": "ISO-8601 timestamp"
}

Parameters:
    - min_score (float)
        Minimum CVSS score threshold for filtering CVEs

--------------------------------------------------------------------------------
OUTPUTS
--------------------------------------------------------------------------------

Return Object:
    new_cves (list[dict])
        List of previously unseen CVEs

    stats (dict)
        Processing metadata:
        - total_processed
        - new_this_run
        - timestamp

State File Updated:
    processed_cves.json

--------------------------------------------------------------------------------
ROLE IN PIPELINE
--------------------------------------------------------------------------------

This module ensures:

    - No duplicate alerts in SOC workflows
    - Incremental CVE processing
    - Persistent state across executions
    - Efficient filtering of intelligence data

It is a core component of the alert deduplication layer.

--------------------------------------------------------------------------------
USE CASES
--------------------------------------------------------------------------------

- SOC alert deduplication
- Threat intelligence pipelines
- CVE monitoring systems
- Automated security alerting systems

================================================================================
"""

# ==============================================================================
# IMPORTS
# ==============================================================================

import os
import json
import sqlite3
from datetime import datetime

from collect_cves import DB_FILE


# ==============================================================================
# CONFIGURATION
# ==============================================================================

BASE_DIR = os.path.dirname(__file__)

STATE_FILE = os.path.join(BASE_DIR, "processed_cves.json")


# ==============================================================================
# STATE MANAGEMENT
# ==============================================================================

def load_processed_cves():
    """
    Load previously processed CVE IDs from state file.

    Returns
    -------
    set
        Set of processed CVE IDs
    """

    if not os.path.exists(STATE_FILE):
        return set()

    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return set(data.get("ids", []))

    except (json.JSONDecodeError, OSError):
        return set()


def save_processed_cves(processed_ids):
    """
    Save processed CVE IDs to persistent state file.
    """

    payload = {
        "ids": list(processed_ids),
        "last_run": datetime.utcnow().isoformat()
    }

    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


# ==============================================================================
# CORE DEDUPLICATION LOGIC
# ==============================================================================

def get_new_high_critical_cves(min_score=7.0):
    """
    Retrieve new HIGH/CRITICAL CVEs not yet processed.

    Parameters
    ----------
    min_score : float
        CVSS score threshold

    Returns
    -------
    tuple
        (new_cves, stats)
    """

    processed_ids = load_processed_cves()

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, published, lastModified, description, score, vector, severity
        FROM cves
        WHERE score IS NOT NULL AND score >= ?
        ORDER BY score DESC
    """, (min_score,))

    rows = cursor.fetchall()
    conn.close()

    new_cves = []
    updated_ids = set(processed_ids)

    for row in rows:
        cve_id = row[0]

        if cve_id not in processed_ids:
            new_cves.append({
                "id": cve_id,
                "published": row[1],
                "lastModified": row[2],
                "description": row[3],
                "score": row[4],
                "vector": row[5],
                "severity": row[6]
            })

            updated_ids.add(cve_id)

    save_processed_cves(updated_ids)

    stats = {
        "total_processed": len(updated_ids),
        "new_this_run": len(new_cves),
        "timestamp": datetime.utcnow().isoformat()
    }

    return new_cves, stats


# ==============================================================================
# CLI TEST MODE
# ==============================================================================

if __name__ == "__main__":

    new_cves, stats = get_new_high_critical_cves()

    print(f"New CVEs detected: {stats['new_this_run']}")
    print(f"Total processed: {stats['total_processed']}")

    for cve in new_cves:
        print(f"- {cve['id']} | {cve['severity']} | {cve['score']}")