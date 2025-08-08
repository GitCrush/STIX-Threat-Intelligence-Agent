# ATT&CK® STIX Threat Intelligence Agent

A modular, open source **Threat Intelligence Agent** for ingesting, querying, and exploring MITRE ATT&CK® STIX datasets via a flexible REST API and AI-powered Bash/GPT conversational interface.

---

##  Overview

This agent enables organizations, analysts, and researchers to:

- **Ingest** STIX data (MITRE ATT&CK®, ICS, Mobile, etc.) into a MongoDB backend
- **Expose** a generic, schema-aware REST API for structured, filterable, and analytic queries over ATT&CK® knowledge objects (techniques, groups, malware, tools, etc.)
- **Search, aggregate, and analyze** ATT&CK® data using standard HTTP, curl, Python, or Bash shell scripts
- **Leverage Generative AI** (GPT-4/4o) for natural language questions, with auto-conversion to Bash scripts for complex threat identification and data exploration
- **Extend** to other STIX-like datasets, or custom data, thanks to generic data and API logic

---

##  Features

- **FastAPI** REST backend with robust, generic endpoints
- **Flexible filtering and free-text search** on any valid field (as per `/api/v1/schema`)
- **Dynamic schema discovery** for API self-documentation and GPT prompt injection
- **Chained/analytic queries** (e.g., "top 5 techniques used by APT29, and their mitigations")
- **Group-by/aggregation endpoints** for per-tactic, per-platform, or per-domain analytics
- **Bash Scripting Assistant**: Natural language prompt → auto-generated bash scripts (curl+jq) ready for CLI or notebook execution
- **Extensible**: Easily plug in new datasets or custom entities by mapping collections in MongoDB

---

##  Installation

### 1. Prerequisites

- **Python 3.9+**
- **MongoDB** running locally or remote
- **jq** and **curl** (for Bash/GPT integration)

### 2. Clone the Repository

```bash
git clone https://github.com/gitcrush/threat-intel-agent.git
cd threat-intel-agent
```
---

## 3. Python Environment

Set up and activate a virtual environment, then install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---


## 4. MongoDB Setup

- Ensure `mongod` is running (default URI: `mongodb://localhost:27017/`).
- Default database: **`mitre_attack`**.

---

##  Data Ingestion — Ingest MITRE ATT&CK® STIX Bundles

1. Place STIX JSON files (from https://github.com/mitre/cti) in a local directory (e.g., `./stix_data/`).
2. Run the provided ingestion script to load ATT&CK® (enterprise, mobile, ICS, etc.) and any other STIX datasets:

```bash
python ingestor.py --stix_dir ./stix_data/
```

- The ingestor is **schema-generic**: any STIX bundle (groups, malware, techniques, etc.) is mapped to the correct MongoDB collection.
- The schema is auto-discovered and reflected at **`/api/v1/schema`**.

---

##  API Usage

Start the API server:

```bash
uvicorn main:app --reload --port 8000
```

### Key Endpoints

- **Entity listing/filtering**  
  `/api/v1/{entity}?filter_by=field:value&top=N&by=field`

- **Entity by ID**  
  `/api/v1/{entity}/{id}`

- **Relationships**  
  `/api/v1/relationships?type=uses&source=...&target=...`

- **Dynamic schema**  
  `/api/v1/schema`

- **Full-text search**  
  `/api/v1/search?q=banking&entity=malware`

- **Group-by analytics**  
  `/api/v1/techniques/groupby?field=kill_chain_phases.phase_name&top=5&by=groups`

- **Chained/analytic POST**  
  `/api/v1/query` (POST with JSON chain steps)

> See interactive API docs at **`/docs`** when the server is running!

---

##  Natural Language Querying (GPT/Bash)

The agent ships with a conversational CLI (`gpt_executor.py`) to ask natural-language questions and get a ready-to-run Bash script using the API.

**Example usage:**

```bash
python gpt_executor.py
```

**Sample interaction:**

> Ask your threat intel question (or 'exit'): **top 5 techniques used by FIN7 in mobile attacks**

** GPT generates:**
```bash
body='[
  {"entity": "groups", "selection": "fin7"},
  {"relationship": "uses", "entity": "techniques", "selection": "top5", "filters": {"x_mitre_domains": "mobile-attack"}}
]'
curl -s -X POST "http://localhost:8000/api/v1/query" -H "Content-Type: application/json" -d "$body" | jq
```

**Explanation:** Finds top 5 mobile techniques used by FIN7, leveraging entity and relationship filtering.

- **Multi-step questions** are handled via POST `/api/v1/query` or group-by endpoints.
- All valid filters/fields are **auto-discovered** via `/api/v1/schema`.

---

##  Customization & Extending

- **Add new entity types:** Ingest any valid STIX JSON or map new MongoDB collections in `ENTITY_COLLECTION`.
- **Schema awareness:** The API and GPT prompt are always up-to-date via `/api/v1/schema`.
- **API self-documenting:** `/docs` auto-documents all REST methods and schemas.

---

##  Example Use Cases

- **Threat Hunting:** “Show techniques with most recent usage by ransomware groups in 2024”
- **Red Team / Blue Team Analysis:** “List mitigations for all credential access techniques”
- **Cybersecurity Research:** “Find trends in attack techniques across domains over time”
- **Automation:** Integrate with SIEMs or SOARs for real-time enrichment

---

##  License and MITRE Terms of Use

This software is open source under the **MIT License**.

**MITRE ATT&CK® and STIX Notice:**

- MITRE ATT&CK® and STIX are trademarks of The MITRE Corporation. This software utilizes MITRE ATT&CK® data, which is made available to the public by MITRE under the [ATT&CK® Terms of Use](https://attack.mitre.org/resources/terms-of-use/). Use of the ATT&CK® data via this agent must comply with those terms.
- This project is neither affiliated with nor endorsed by MITRE.  
- All ATT&CK® content and original STIX datasets remain copyright MITRE.

---


##  Documentation

- **API Reference:** `/docs` (running server)
- **System prompt:** see `docs/`

