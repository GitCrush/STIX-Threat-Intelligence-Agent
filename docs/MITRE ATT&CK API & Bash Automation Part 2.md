======================================================================
MITRE ATT&CK API & Bash Automation: Comprehensive Documentation
======================================================================

Part 2: Data Retrieval, Filtering, Relationships, Group-By, and Search
----------------------------------------------------------------------

1. DATA RETRIEVAL BASICS

- **Standard Entity Listing**  
  Retrieve all or a subset of entities:

curl -s "http://localhost:8000/api/v1/groups" | jq
curl -s "http://localhost:8000/api/v1/malware?top=10&by=recent" | jq

- Use `top=N` to limit, and `by=field` to sort/aggregate.  
- Use `/api/v1/{entity}` for generic access (see Part 1).

- **Entity by ID**

curl -s "http://localhost:8000/api/v1/groups/intrusion-set--G001" | jq


2. ADVANCED FILTERING

- **Flexible Filtering**  
Any listing endpoint accepts repeated `filter_by=field:value` parameters for AND-combined filters.
- Field names must be present in `/api/v1/schema`.
- Supports top-level and subfields (dot notation).
- Examples:
  ```
  curl -s "http://localhost:8000/api/v1/techniques?filter_by=x_mitre_domains:enterprise-attack&filter_by=platforms:Windows" | jq
  curl -s "http://localhost:8000/api/v1/groups?filter_by=aliases:FIN7" | jq
  curl -s "http://localhost:8000/api/v1/techniques?filter_by=kill_chain_phases.phase_name:collection" | jq
  ```
- **Date Filters**  
Use standard comparison syntax:  

curl -s "http://localhost:8000/api/v1/malware?filter_by=created:>2024-01-01" | jq
curl -s "http://localhost:8000/api/v1/campaigns?filter_by=last_seen:<2022-12-31" | jq



3. RELATIONSHIPS & ANALYTIC CHAINS

- **Relationship Listing**
- Query all relationships, or filter by type/source/target.
  ```
  curl -s "http://localhost:8000/api/v1/relationships?type=uses&source=intrusion-set--fin7-id&target=malware" | jq
  curl -s "http://localhost:8000/api/v1/relationships?type=mitigates&target=attack-pattern--T1055-id" | jq
  ```

- **Multi-Step (Chained) Analytics**
- Use the `/api/v1/query` endpoint for graph traversals or multi-step aggregations.  
- Send a JSON array of steps, e.g.:
  ```
  body='[
    {"entity": "groups", "selection": "top5", "by": "techniques"},
    {"relationship": "uses", "entity": "malware"}
  ]'
  curl -s -X POST "http://localhost:8000/api/v1/query" -H "Content-Type: application/json" -d "$body" | jq
  ```
  - Step 1: Top 5 groups by techniques used.
  - Step 2: For those groups, get malware they use.

- **Examples:**
  - Top 5 mobile techniques (by group usage), then their mitigations:
    ```
    body='[
      {"entity": "techniques", "selection": "top5", "by": "groups", "filters": {"x_mitre_domains": "mobile-attack"}},
      {"relationship": "mitigated-by", "entity": "mitigations"}
    ]'
    curl -s -X POST "http://localhost:8000/api/v1/query" -H "Content-Type: application/json" -d "$body" | jq
    ```

4. GROUP-BY QUERIES: ADVANCED AGGREGATION

- **Purpose**: Group results by any (sub)field, sort, and return top N per group—server-side aggregation for scalable analytics.

- **Endpoint**:  

GET /api/v1/{entity}/groupby?field=<field>&top=N&by=<metric>[&filters=...]

- `entity`: techniques, malware, etc.
- `field`: grouping field (dot notation supported)
- `top`: N per group
- `by`: metric to rank (e.g., groups, name)
- `filters`: (optional) JSON string with extra filters

- **Examples:**
  - Top 5 techniques per kill chain phase (by group usage):
    ```
    curl -s "http://localhost:8000/api/v1/techniques/groupby?field=kill_chain_phases.phase_name&top=5&by=groups" | jq 'to_entries[] | {phase: .key, techniques: [.value[].name]}'
    ```
  - Top 3 malware per platform for mobile attacks:
    ```
    curl -s "http://localhost:8000/api/v1/malware/groupby?field=x_mitre_platforms&top=3&by=groups&filters={\"x_mitre_domains\":\"mobile-attack\"}" | jq 'to_entries[] | {platform: .key, malware: [.value[].name]}'
    ```

- **Best Practices**:
  - Use groupby endpoint for all "top N per [field]" needs—do not loop or aggregate in client if possible.
  - If a field is not groupable, API will return a clear error message.

5. FREE-TEXT SEARCH

- **Endpoint**:  

GET /api/v1/search?q=<search_term>[&entity=<entity_type>][&filter_by=field:value ...]

- `q`: free-text term, matches anywhere in `name`, `description`, or `aliases` (case-insensitive).
- `entity`: restricts to a single entity type.
- `filter_by`: combine with additional filters.

- **Examples:**
  - Techniques mentioning VPN in enterprise:
    ```
    curl -s "http://localhost:8000/api/v1/search?q=vpn&entity=techniques&filter_by=x_mitre_domains:enterprise-attack" | jq
    ```
  - Mobile malware with "banking" in description:
    ```
    curl -s "http://localhost:8000/api/v1/search?q=banking&entity=malware&filter_by=x_mitre_domains:mobile-attack" | jq
    ```

- **When to Use**:
  - When the user query is ambiguous or maps to any text field.
  - For discovery or when field mapping is not direct.

---

6. BASH AUTOMATION: BEST PRACTICES

- Always use double quotes around URLs to avoid issues with `&` and shell expansion.
- Use `jq` for filtering, extraction, aggregation, and pretty-printing.
- For multi-step or comparative analytics, use bash variables:
  ```
  count2024=$(curl -s "..." | jq 'length')
  count2025=$(curl -s "..." | jq 'length')
  echo "2024: $count2024"
  echo "2025: $count2025"
  echo "Change: $((count2025 - count2024))"
  ```
- Always include `EXPLANATION` (in your scripts or documentation) to clarify why this is the best approach for the user's question.

---

7. ERROR HANDLING

- If a query cannot be fulfilled (no data, unsupported field/grouping, etc.), echo a clear error message and explain why in the `EXPLANATION`.

---

END OF PART 2

======================================================================
