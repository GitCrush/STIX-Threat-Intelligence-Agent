======================================================================
MITRE ATT&CK API & Bash Automation: Comprehensive Documentation
======================================================================

Part 3: Advanced Use Cases, Extensibility, and Integration (REVISED)
----------------------------------------------------------------------

1. ADVANCED USE CASES

- **Multi-Year, Multi-Factor Analytics with ISO Dates**
    - Date/time fields such as `created` and `modified` use ISO 8601 format, e.g., `"2025-04-16T21:26:15.157000"`.
    - When filtering by year, use string comparison or substring logic (not arithmetic on the timestamp).
    - Example: Compare malware created in 2023 vs 2024
      ```bash
      count2023=$(curl -s "http://localhost:8000/api/v1/malware" | jq '[.[] | select(.created | startswith("2023-"))] | length')
      count2024=$(curl -s "http://localhost:8000/api/v1/malware" | jq '[.[] | select(.created | startswith("2024-"))] | length')
      echo "2023: $count2023"
      echo "2024: $count2024"
      echo "Change: $((count2024 - count2023))"
      ```
    - If the API supports `filter_by=created:>2023-01-01`, that can be used as well, but substring is robust for ISO dates.

- **Discovery/Enrichment by Free-Text Search**
    - Find all campaigns, groups, or techniques mentioning a term, then aggregate or filter.
    - Example:
      ```bash
      ids=$(curl -s "http://localhost:8000/api/v1/search?q=phishing&entity=techniques" | jq -r '.[].id')
      for id in $ids; do
        curl -s "http://localhost:8000/api/v1/techniques/$id" | jq '.name'
      done
      ```

- **Complex Chaining Across Entities**
    - Combine endpoints for questions like: “Which groups use malware created in 2025?”
    - Example:
      ```bash
      malware_ids=$(curl -s "http://localhost:8000/api/v1/malware" | jq -r '[.[] | select(.created | startswith("2025-")) | .id ] | .[]')
      for id in $malware_ids; do
        curl -s "http://localhost:8000/api/v1/relationships?type=uses&target=$id&source=intrusion-set" | jq
      done
      ```

- **Aggregating Over Grouped Results**
    - Use `/groupby` endpoints and `jq`:
      ```bash
      curl -s "http://localhost:8000/api/v1/techniques/groupby?field=x_mitre_platforms&top=3&by=groups" | jq 'to_entries[] | {platform: .key, techniques: [.value[].name]}'
      ```

2. INTEGRATION & PIPELINING

- **Shell Pipeline**
    - Results from one query piped to further jq/shell processing.
    - Example: Count all techniques for "initial-access" phase in 2025:
      ```bash
      curl -s "http://localhost:8000/api/v1/techniques" | jq '[.[] | select(.kill_chain_phases[].phase_name == "initial-access" and .created | startswith("2025-"))] | length'
      ```

- **Integration with External Tools**
    - Example:
      ```bash
      count=$(curl -s "http://localhost:8000/api/v1/groups?filter_by=x_mitre_domains:mobile-attack" | jq 'length')
      echo "Mobile threat groups: $count" | mail -s "Threat Update" analyst@example.com
      ```

- **Batch Processing and Scheduling**
    - Use `cron` to automate such queries and reporting.

3. SCHEMA/DATASET EXTENSIBILITY

- **Generic Entity Endpoint**
    - `/api/v1/{entity}` and `/api/v1/schema` enable dynamic schema awareness.

- **Adapting to New Fields or Entities**
    - Use `/api/v1/schema` in scripts to discover fields, then adjust jq, filters, or grouping dynamically.
    - Example: 
      ```bash
      curl -s "http://localhost:8000/api/v1/schema" | jq
      ```

- **Custom Dataset Integration**
    - Import new STIX or JSON datasets, then access via the generic endpoints.

4. ERROR HANDLING & LIMITATIONS

- **API Error Responses**
    - Endpoints return clear errors for unknown fields/entities.
    - Scripts should check for empty or error results and print messages.

- **Common Limitations**
    - No predictive analytics or trend lines—only descriptive data by timestamp.
    - Date logic is string/ISO based; no built-in "year" or timestamp arithmetic.
    - Use substring or comparison for filtering by year.

5. BEST PRACTICES & TIPS

- Always quote URLs for curl.
- Use jq for all post-processing, extraction, and stats.
- When dealing with ISO date fields, use `startswith("YYYY-")` for year-based filtering in jq.
- Prefer server-side filters when available, but use jq locally when more flexibility is needed.

6. EXAMPLES OF ADVANCED SCENARIOS

- **Top N per group with filtering**
    - Top 3 techniques per platform in mobile domain:
      ```bash
      curl -s "http://localhost:8000/api/v1/techniques/groupby?field=x_mitre_platforms&top=3&by=groups&filters={\"x_mitre_domains\":\"mobile-attack\"}" | jq 'to_entries[] | {platform: .key, techniques: [.value[].name]}'
      ```

- **Comparative Analytics Using ISO Date Format**
    - Compare malware created per year:
      ```bash
      for year in 2023 2024 2025; do
        count=$(curl -s "http://localhost:8000/api/v1/malware" | jq "[.[] | select(.created | startswith(\"$year-\"))] | length")
        echo "$year: $count"
      done
      ```

- **Chained Queries Across Entities with ISO Dates**
    - Find mitigations for techniques created in 2025:
      ```bash
      tech_ids=$(curl -s "http://localhost:8000/api/v1/techniques" | jq -r '[.[] | select(.created | startswith("2025-")) | .id] | .[]')
      for id in $tech_ids; do
        curl -s "http://localhost:8000/api/v1/relationships?type=mitigated-by&target=$id" | jq
      done
      ```

======================================================================

END OF PART 3 (REVISED)
