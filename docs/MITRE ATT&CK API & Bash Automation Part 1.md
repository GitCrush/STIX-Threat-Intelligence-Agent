======================================================================
MITRE ATT&CK API & Bash Automation: Comprehensive Documentation
======================================================================

Part 1: API Structure, Entities, and Schema Discovery
------------------------------------------------------

1. INTRODUCTION

This documentation describes how to use the MITRE ATT&CK API and the accompanying bash scripting interface for advanced, analyst-grade threat intelligence queries and automation. The MITRE ATT&CK dataset is exposed as a flexible REST API, supporting generic, schema-aware access and automation via bash/curl/jq.

This Part 1 explains the API structure, discovery mechanisms, and the generic approach for working with any current or future schema.

---

2. ENTITY MODEL & ENDPOINTS

The API organizes MITRE ATT&CK content into the following entity types:

- groups
- techniques
- malware
- tools
- mitigations
- campaigns

Entities are stored in backend collections with possible different canonical names. The API supports user-friendly endpoints mapped to these collections.

**Main Entity Endpoints:**

- `GET /api/v1/groups`
- `GET /api/v1/techniques`
- `GET /api/v1/malware`
- `GET /api/v1/tools`
- `GET /api/v1/mitigations`
- `GET /api/v1/campaigns`

Each entity endpoint supports:
- Pagination and sorting (`top`, `by`)
- Filtering by arbitrary fields (`filter_by=field:value`, repeatable)

**Examples:**

- List all malware:
    ```
    curl -s "http://localhost:8000/api/v1/malware" | jq
    ```
- Get the top 10 most recent techniques:
    ```
    curl -s "http://localhost:8000/api/v1/techniques?top=10&by=recent" | jq
    ```

---

3. SCHEMA DISCOVERY

The API supports dynamic schema discovery via:

- `GET /api/v1/entities`
    - Lists all available entity types.
    - Example:
        ```
        curl -s "http://localhost:8000/api/v1/entities"
        ```
        Result:
        ```
        {"entities":["campaigns","groups","malware","mitigations","techniques","tools"]}
        ```

- `GET /api/v1/schema`
    - Returns a JSON object listing all valid fields for each entity type, including top-level and subfields (dot notation).
    - Example:
        ```
        curl -s "http://localhost:8000/api/v1/schema" | jq
        ```
    - Typical output:
        ```
        {
          "groups": [
            "aliases", "created", "name", "description", ...
          ],
          "techniques": [
            "name", "kill_chain_phases.phase_name", "description", ...
          ],
          ...
        }
        ```

- **Why is this important?**
    - You can build generic, schema-driven tools and scripts that discover and adapt to the entity types and fields at runtime, without any hard-coding of field names or database internals.
    - Filters and sorts should only use field names present in `/api/v1/schema`.

---

4. GENERIC ENTITY ENDPOINT

For advanced or future-proof automation, the API exposes:

- `GET /api/v1/{entity}`
    - Generic catch-all entity listing endpoint.
    - Accepts both canonical entity names (e.g., `techniques`) and collection names (`attack_patterns`).
    - Behaves exactly like the dedicated endpoints but allows more dynamic scripting.

    Example:
    ```
    curl -s "http://localhost:8000/api/v1/techniques?top=5&filter_by=platforms:Windows"
    ```

    If you add new entity types to the database and schema, this endpoint will immediately support them.

---

5. FIELD FILTERING & DISCOVERY

- Filter any listing endpoint on any field listed in the schema using `filter_by`.
    - Examples:
        ```
        curl -s "http://localhost:8000/api/v1/groups?filter_by=x_mitre_domains:enterprise-attack"
        curl -s "http://localhost:8000/api/v1/techniques?filter_by=kill_chain_phases.phase_name:impact"
        ```
    - You can use multiple `filter_by` params in a single query.
- To discover which fields are valid for filtering/sorting, always check `/api/v1/schema`.

---

6. RELATIONSHIPS

The API models links between entities (e.g., which groups use which techniques) as relationships.

- `GET /api/v1/relationships`
    - Query by type, source, target, with all fields filterable.
    - List available types using `/api/v1/relationships`.

    Example:
    ```
    curl -s "http://localhost:8000/api/v1/relationships?type=uses&source=intrusion-set--apt29-id"
    ```

---

7. GROUP-BY & AGGREGATION

To support advanced analytics:
- `/api/v1/{entity}/groupby?field=<field>&top=N&by=<metric>[&filters=...]`

    - Group results by any field (including subfields).
    - Sort and limit top N per group.
    - Combine with filters for analytic queries.

    Example:
    ```
    curl -s "http://localhost:8000/api/v1/techniques/groupby?field=kill_chain_phases.phase_name&top=5&by=groups" | jq 'to_entries[] | {phase: .key, techniques: [.value[].name]}'
    ```

---

8. BEST PRACTICES

- Always use `/api/v1/entities` and `/api/v1/schema` to programmatically discover entity types and their fields.
- Use generic scripting patterns to ensure forward compatibility.
- Prefer official endpoints over direct collection access when possible.

---

END OF PART 1

======================================================================
