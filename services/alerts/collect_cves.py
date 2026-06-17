"""
collect_cves.py
================================================================================
Cyber Threat Intelligence Collection Pipeline
================================================================================

This module is responsible for collecting vulnerability intelligence from the
NVD (National Vulnerability Database) API and storing it into a local SQLite
database for further processing by downstream intelligence pipelines.

The system acts as the primary ingestion layer of the Cyber Threat Intelligence
pipeline.

--------------------------------------------------------------------------------
WORKFLOW
--------------------------------------------------------------------------------

STEP 1 — Database Initialization
    Creates the SQLite schema if it does not exist.

STEP 2 — Data Collection (NVD API)
    Fetches recent CVEs from the NVD API based on a time window.

STEP 3 — Data Normalization
    Extracts and normalizes CVE fields (CVSS, severity, description, vector).

STEP 4 — Data Storage
    Inserts or updates CVE records into the local SQLite database.

--------------------------------------------------------------------------------
INPUTS
--------------------------------------------------------------------------------

External API:
    - NVD CVE API
      URL: https://services.nvd.nist.gov/rest/json/cves/2.0

Parameters:
    - hours_back (int)
        Defines the time window for CVE retrieval (default: 24h)

--------------------------------------------------------------------------------
OUTPUTS
--------------------------------------------------------------------------------

SQLite Database:
    - cve_data.db

Table: cves

Schema:
    - id (TEXT PRIMARY KEY)
    - published (TEXT)
    - lastModified (TEXT)
    - description (TEXT)
    - score (REAL)
    - vector (TEXT)
    - severity (TEXT)

Returned Data:
    - List of normalized CVE dictionaries
    - Inserted row count

--------------------------------------------------------------------------------
DEPENDENCIES
--------------------------------------------------------------------------------

- requests
- sqlite3
- datetime
- os

--------------------------------------------------------------------------------
USE CASES
--------------------------------------------------------------------------------

- Daily vulnerability ingestion
- SOC threat intelligence pipeline
- CVE monitoring automation
- Security reporting systems

================================================================================
"""

# ==============================================================================
# IMPORTS
# ==============================================================================

import os
import sqlite3
import requests
from datetime import datetime, timedelta

# ==============================================================================
# CONFIGURATION
# ==============================================================================

DB_FILE = os.path.join(os.path.dirname(__file__), "cve_data.db")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ==============================================================================
# DATABASE INITIALIZATION
# ==============================================================================

def init_db():
    """
    Initializes SQLite database schema if not exists.
    """

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS cves (
        id TEXT PRIMARY KEY,
        published TEXT,
        lastModified TEXT,
        description TEXT,
        score REAL,
        vector TEXT,
        severity TEXT
    )
    """)

    conn.commit()
    conn.close()


# ==============================================================================
# CVE FETCHING FROM NVD API
# ==============================================================================

def fetch_recent_cves(hours_back=24):
    """
    Fetches CVEs updated within the last X hours from NVD API.
    """

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours_back)

    params = {
        "lastModStartDate": start_time.isoformat() + "Z",
        "lastModEndDate": end_time.isoformat() + "Z",
        "resultsPerPage": 2000
    }

    print(f"🔎 Fetching CVEs from NVD (last {hours_back} hours)...")

    response = requests.get(NVD_URL, params=params, timeout=20)

    if response.status_code != 200:
        print("❌ NVD API error:", response.text)
        return []

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    results = []

    for item in vulnerabilities:

        cve = item.get("cve", {})

        cve_id = cve.get("id")
        published = cve.get("published")
        last_modified = cve.get("lastModified")

        description = ""
        desc_data = cve.get("descriptions", [])
        if desc_data:
            description = desc_data[0].get("value", "")

        score = None
        severity = None
        vector = None

        metrics = cve.get("metrics", {})

        cvss_data = None

        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0]["cvssData"]

        if cvss_data:
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity")
            vector = cvss_data.get("vectorString")

        results.append({
            "id": cve_id,
            "published": published,
            "lastModified": last_modified,
            "description": description,
            "score": score,
            "vector": vector,
            "severity": severity
        })

    print(f"✅ {len(results)} CVEs retrieved from NVD.")

    return results


# ==============================================================================
# DATABASE STORAGE
# ==============================================================================

def save_cves(cves):
    """
    Saves CVE list into SQLite database (insert or replace).
    """

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    inserted = 0

    for entry in cves:
        try:
            c.execute("""
            INSERT OR REPLACE INTO cves
            (id, published, lastModified, description, score, vector, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                entry["id"],
                entry["published"],
                entry["lastModified"],
                entry["description"],
                entry["score"],
                entry["vector"],
                entry["severity"]
            ))

            inserted += 1

        except Exception as e:
            print("Insertion error:", e)

    conn.commit()
    conn.close()

    print(f"💾 {inserted} CVEs stored in database.")

    return inserted


# ==============================================================================
# PIPELINE ENTRY POINT
# ==============================================================================

if __name__ == "__main__":

    init_db()

    cves = fetch_recent_cves(24)

    save_cves(cves)