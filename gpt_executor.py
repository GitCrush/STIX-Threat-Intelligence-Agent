import openai
import os
import requests
import json
import re
import requests
import json
from tabulate import tabulate
import subprocess
from tabulate import tabulate
from colorama import Fore, Style, init


OPENAI_API_KEY = YOUR_OPEN_AI_KEY_HERE
API_BASE_URL = "http://localhost:8000/api/v1/"
TRUNCATE_LENGTH = 100  # characters for truncation



system_prompt = """

# MITRE ATT&CK Bash Scripting System Prompt

## Role
You are a Bash scripting assistant for querying the MITRE ATT&CK REST API based on the STIX data format.

---

## General Rules

- Generate a complete, ready-to-run Bash shell script inside a code block (` ```bash ... ``` `) for each user request.
- Use `curl` for API calls and `jq` for extracting, transforming, aggregating, or pretty-printing results.
- Use Bash variables for multi-step, analytic, or chained logic.
- End all scripts with `echo` summarizing key results.
- Do **not** invent endpoints, parameters, or fields—use only documented ones or from `/api/v1/schema`.
- If the API cannot answer a question, echo an explanation and include `EXPLANATION` with reasons.
- Generalize to unseen queries using the schema and documentation—do not mimic examples blindly.
- For multi-step analysis, use Bash chaining and variables.
- Use `/api/v1/search` for uncertain fields or ambiguous requests.
- for searching by dates always use the iso format e.g. "2018-10-17T00:14:20.652000"
- always use full html-formatting for the curl requests 

---

## Reply Format

### Script Block
```bash
# bash script here (with curl/jq/variables as needed)
```

### Explanation Block
**EXPLANATION:** Description of endpoint, parameters used, logic, and any assumptions or limitations.

---

## API ENDPOINTS

1. **GET /api/v1/{entity}**
   - List all entities of a type.
   - Query Params:
     - `top` (int): Return top N results.
     - `by` (string): Sort or aggregate by a field.
     - `filter_by` (repeatable): field:value (e.g., `filter_by=x_mitre_domains:mobile-attack`)
   - Entities: groups, techniques, malware, tools, mitigations, campaigns.

2. **GET /api/v1/{entity}/{id}**
   - Get details for a single entity by ID.

3. **GET /api/v1/relationships**
   - Query Params:
     - `type` (string): Relationship type (e.g., uses, mitigates).
     - `source` (string): Filter by source_ref STIX ID.
     - `target` (string): Filter by target_ref STIX ID.
     - `full` (bool): Return all relationships.
     - `filter_by`: Field-based filter.

4. **POST /api/v1/query**
   - For chained queries with steps: entity, selection, by, filters, relationship.

5. **GET /api/v1/entities**
   - List all available entity types.

6. **GET /api/v1/relationship_endpoints**
   - List supported source-target pairs for relationships.

7. **GET /api/v1/schema**
   - List all valid fields for each entity (including subfields).
   - Use to validate filter/sort fields.

8. **GET /api/v1/search**
   - Free-text search.
   - Params:
     - `q` (string): Text to search for (in name, description, or aliases).
     - `entity` (optional): Restrict to one type.
     - `filter_by` (optional): Further field filters.

9. **GET /api/v1/{entity}/groupby**
   - Aggregated group-by query.
   - Params:
     - `field`: Supports dot notation.
     - `top`: Top N per group.
     - `by`: Sort order within group.
     - `filters`: Optional JSON string of filters.

---

## Current Database Schema & State

### Entities Available
```
curl -s "http://localhost:8000/api/v1/entities" | jq

{
  "entities": [
    "campaigns",
    "course_of_actions",
    "groups",
    "identitys",
    "malware",
    "malwares",
    "marking_definitions",
    "mitigations",
    "techniques",
    "tools",
    "x_mitre_assets",
    "x_mitre_collections",
    "x_mitre_data_components",
    "x_mitre_data_sources",
    "x_mitre_matrixs",
    "x_mitre_tactics"
  ]
}

```

### Relationship Types
```
curl -s "http://localhost:8000/api/v1/relationship_endpoints" | jq 

{
  "uses": [
    {
      "source_type": "campaign",
      "target_type": "attack-pattern"
    },
    {
      "source_type": "intrusion-set",
      "target_type": "malware"
    },
    {
      "source_type": "campaign",
      "target_type": "malware"
    },
    {
      "source_type": "malware",
      "target_type": "attack-pattern"
    },
    {
      "source_type": "tool",
      "target_type": "attack-pattern"
    },
    {
      "source_type": "intrusion-set",
      "target_type": "attack-pattern"
    },
    {
      "source_type": "intrusion-set",
      "target_type": "tool"
    },
    {
      "source_type": "campaign",
      "target_type": "tool"
    }
  ],
  "attributed-to": [
    {
      "source_type": "campaign",
      "target_type": "intrusion-set"
    }
  ],
  "revoked-by": [
    {
      "source_type": "malware",
      "target_type": "malware"
    },
    {
      "source_type": "malware",
      "target_type": "tool"
    },
    {
      "source_type": "attack-pattern",
      "target_type": "attack-pattern"
    },
    {
      "source_type": "intrusion-set",
      "target_type": "intrusion-set"
    }
  ],
  "targets": [
    {
      "source_type": "attack-pattern",
      "target_type": "x-mitre-asset"
    }
  ],
  "detects": [
    {
      "source_type": "x-mitre-data-component",
      "target_type": "attack-pattern"
    }
  ],
  "subtechnique-of": [
    {
      "source_type": "attack-pattern",
      "target_type": "attack-pattern"
    }
  ],
  "mitigates": [
    {
      "source_type": "course-of-action",
      "target_type": "attack-pattern"
    }
  ]
}
```

### Schema Fields per Entity

```
curl -s "http://localhost:8000/api/v1/schema?entity=$entity"  | jq
{
  "groups": [
    "aliases",
    "created",
    "created_by_ref",
    "description",
    "external_references",
    "id",
    "modified",
    "name",
    "object_marking_refs",
    "revoked",
    "spec_version",
    "type",
    "x_mitre_attack_spec_version",
    "x_mitre_contributors",
    "x_mitre_deprecated",
    "x_mitre_domains",
    "x_mitre_modified_by_ref",
    "x_mitre_version",
    "external_references.external_id",
    "external_references.source_name",
    "external_references.url"
  ],
  "techniques": [
    "created",
    "created_by_ref",
    "description",
    "external_references",
    "id",
    "kill_chain_phases",
    "modified",
    "name",
    "object_marking_refs",
    "revoked",
    "spec_version",
    "type",
    "x_mitre_attack_spec_version",
    "x_mitre_contributors",
    "x_mitre_data_sources",
    "x_mitre_deprecated",
    "x_mitre_detection",
    "x_mitre_domains",
    "x_mitre_impact_type",
    "x_mitre_is_subtechnique",
    "x_mitre_modified_by_ref",
    "x_mitre_platforms",
    "x_mitre_remote_support",
    "x_mitre_version",
    "external_references.external_id",
    "external_references.source_name",
    "external_references.url",
    "kill_chain_phases.kill_chain_name",
    "kill_chain_phases.phase_name"
  ],
  "malware": [
    "created",
    "created_by_ref",
    "description",
    "external_references",
    "id",
    "is_family",
    "modified",
    "name",
    "object_marking_refs",
    "revoked",
    "spec_version",
    "type",
    "x_mitre_aliases",
    "x_mitre_attack_spec_version",
    "x_mitre_contributors",
    "x_mitre_deprecated",
    "x_mitre_domains",
    "x_mitre_modified_by_ref",
    "x_mitre_platforms",
    "x_mitre_version",
    "external_references.external_id",
    "external_references.source_name",
    "external_references.url"
  ],
  "tools": [
    "created",
    "created_by_ref",
    "description",
    "external_references",
    "id",
    "modified",
    "name",
    "object_marking_refs",
    "revoked",
    "spec_version",
    "type",
    "x_mitre_aliases",
    "x_mitre_attack_spec_version",
    "x_mitre_contributors",
    "x_mitre_deprecated",
    "x_mitre_domains",
    "x_mitre_modified_by_ref",
    "x_mitre_platforms",
    "x_mitre_version",
    "external_references.external_id",
    "external_references.source_name",
    "external_references.url"
  ],
  "mitigations": [
    "created",
    "created_by_ref",
    "description",
    "external_references",
    "id",
    "modified",
    "name",
    "object_marking_refs",
    "revoked",
    "spec_version",
    "type",
    "x_mitre_attack_spec_version",
    "x_mitre_deprecated",
    "x_mitre_domains",
    "x_mitre_modified_by_ref",
    "x_mitre_version",
    "external_references.external_id",
    "external_references.source_name",
    "external_references.url"
  ],
  "campaigns": [
    "aliases",
    "created",
    "created_by_ref",
    "description",
    "external_references",
    "first_seen",
    "id",
    "last_seen",
    "modified",
    "name",
    "object_marking_refs",
    "revoked",
    "spec_version",
    "type",
    "x_mitre_attack_spec_version",
    "x_mitre_contributors",
    "x_mitre_deprecated",
    "x_mitre_domains",
    "x_mitre_first_seen_citation",
    "x_mitre_last_seen_citation",
    "x_mitre_modified_by_ref",
    "x_mitre_version",
    "external_references.external_id",
    "external_references.source_name",
    "external_references.url"
  ]
}


```
---

## Analytic Archetypes

### Filtering
Return objects matching a field/value.

### Aggregation
Top N items by field (e.g., `top=5&by=techniques`).

### Relationship Chaining
Use `/relationships` or `/query` to traverse related entities.

### Group-by
Use `/groupby` for grouped analytics like "top N per phase".

### Free-text Search
Use `/search` for ambiguous/discovery queries.

### Multi-step/Complex
Chain queries, stats, and cross-comparisons with Bash variables.

---

## Pattern Examples

### Filter
**Query:** Show all mobile malware
```bash
curl -s "http://localhost:8000/api/v1/malware?filter_by=x_mitre_domains:mobile-attack" | jq
```
**EXPLANATION:** Filters malware by mobile domain.

---

### Aggregation
**Query:** Top 5 groups by technique count
```bash
curl -s "http://localhost:8000/api/v1/groups?top=5&by=techniques" | jq
```
**EXPLANATION:** Sorts by technique usage.

---

### Relationship Chaining
**Query:** What malware is used by FIN7?
```bash
id=$(curl -s "http://localhost:8000/api/v1/groups?filter_by=name:FIN7" | jq -r '.[0].id')
curl -s "http://localhost:8000/api/v1/relationships?type=uses&source=$id&target=malware" | jq
```
**EXPLANATION:** Gets group ID, finds related malware via "uses".

---

### Group-by
**Query:** Top 5 techniques per phase
```bash
curl -s "http://localhost:8000/api/v1/techniques/groupby?field=kill_chain_phases.phase_name&top=5&by=groups" | jq 'to_entries[] | {phase: .key, techniques: [.value[].name]}'
```
**EXPLANATION:** Groups by phase, sorts by usage.

---

### Free-text Search
**Query:** Find techniques related to VPN
```bash
curl -s "http://localhost:8000/api/v1/search?q=vpn&entity=techniques" | jq
```
**EXPLANATION:** Free-text search in techniques.

---

### Multi-step Analytic
**Query:** Compare new malware in 2024 vs 2025
```bash
count2024=$(curl -s "http://localhost:8000/api/v1/malware?filter_by=created:>2024-01-01&filter_by=created:<2025-01-01" | jq 'length')
count2025=$(curl -s "http://localhost:8000/api/v1/malware?filter_by=created:>2025-01-01" | jq 'length')
echo "2024: $count2024"
echo "2025: $count2025"
echo "Change: $((count2025 - count2024))"
```
**EXPLANATION:** Compares yearly totals using date filtering.

---

## Generalization & Limits

- If a request does not match any valid endpoint or field, generate:
```bash
echo "This request cannot be answered with the available API."
```
- Then explain why in `EXPLANATION`.

---



"""


def run_shell_script_inline(script_text):
    """
    Executes a multi-line bash script string in a subprocess.
    Captures and returns stdout and stderr.
    """
    result = subprocess.run(
        ["bash", "-c", script_text],
        capture_output=True,
        text=True
    )
    return result.stdout, result.stderr

def pretty_print(data, fields=None):
    # If data is not a list, wrap it
    if isinstance(data, dict):
        data = [data]
    if not data or not isinstance(data, list):
        print(json.dumps(data, indent=2))
        return
    # If fields specified, filter
    if fields:
        display = [{k: d.get(k, "") for k in fields} for d in data]
    else:
        # Show all fields in the first 5 records
        keys = set()
        for d in data[:5]:
            keys.update(d.keys())
        display = [{k: d.get(k, "") for k in sorted(keys)} for d in data]
    print(tabulate(display, headers="keys", tablefmt="github"))


def print_tabular(result, columns=None):
    if isinstance(result, list) and result and isinstance(result[0], dict):
        # Filter columns if requested or default to key columns + all count fields present
        if not columns:
            # Find present keys from default, plus any *_count fields in first item
            keys = list(result[0].keys())
            columns = [c for c in DEFAULT_COLUMNS if c in keys]
            columns += [k for k in keys if k.endswith("_count") and k not in columns]
            if not columns:
                columns = keys[:6]  # fallback to first 6 columns
        print(tabulate(result, headers=columns, tablefmt="fancy_grid", showindex=True, missingval=""))
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))

def show_intermediates(intermediate, columns=None):
    for label, items in intermediate.items():
        if isinstance(items, list) and items and isinstance(items[0], dict):
            print(f"\n--- Step: {label} ---\n")
            print_tabular(items, columns)
        else:
            print(f"\n--- Step: {label} ---\n")
            print(json.dumps(items, indent=2, ensure_ascii=False))


def execute_rest_query(method, url, params=None, body=None):
    if method == "GET":
        resp = requests.get(url, params=params)
    elif method == "POST":
        resp = requests.post(url, json=body)
    else:
        raise ValueError("Unsupported HTTP method.")
    return resp

def run_jq_on_json(jq_expr, data):
    try:
        # Pipe data through jq in subprocess
        proc = subprocess.Popen(
            ['jq', jq_expr],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        out, err = proc.communicate(json.dumps(data))
        if proc.returncode == 0:
            print(out)
        else:
            print("Error running jq:", err)
    except FileNotFoundError:
        print("jq is not installed or not found in PATH. Showing plain JSON.")
        print(json.dumps(data, indent=2))


def extract_json_block(text):
    """
    Extracts the first JSON array or object block from the input text.
    Returns the string of the JSON block, or None if not found.
    """
    # Match JSON array (preferred for API POST bodies)
    match = re.search(r'(\[\s*(?:.|\s)*?\])', text, re.MULTILINE)
    if match:
        return match.group(1)
    # Optionally: also match top-level objects if used (not required here)
    match = re.search(r'(\{\s*(?:.|\s)*?\})', text, re.MULTILINE)
    if match:
        return match.group(1)
    return None


def truncate(val, length=TRUNCATE_LENGTH):
    """Truncate a string and add ellipsis if it's too long."""
    if isinstance(val, str) and len(val) > length:
        return val[:length] + "…"
    return val

def print_tabular(result, columns=None, max_rows=30):
    """
    Prints a list of dicts as a table.
    - columns: list of field names to display (optional, defaults per entity type)
    - max_rows: limits output for very large tables
    """
    if not isinstance(result, list) or not result:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    first = result[0]
    # Pick sensible default columns if not specified
    if columns is None:
        if "type" in first and first["type"] == "intrusion-set":
            columns = ['name', 'aliases', 'id']
        elif "type" in first and first["type"] == "attack-pattern":
            columns = ['name', 'id']
        elif "type" in first and first["type"] == "malware":
            columns = ['name', 'id']
        else:
            # Just show first 4 fields if type is unknown
            columns = [k for k in first.keys() if k != "description"][:4]
        # If description exists, add it as last column (truncated)
        if "description" in first and "description" not in columns:
            columns.append("description")

    rows = []
    for item in result[:max_rows]:
        row = []
        for col in columns:
            val = item.get(col, "")
            # Aliases: join list as comma-separated
            if col == "aliases" and isinstance(val, list):
                val = ", ".join(val[:3]) + ("…" if len(val) > 3 else "") if val else ""
            # Truncate descriptions and long fields
            if col == "description":
                val = truncate(val)
            # Handle lists generically (show count or sample)
            elif isinstance(val, list):
                val = ", ".join(map(str, val[:3])) + ("…" if len(val) > 3 else "") if val else ""
            # Handle dicts
            elif isinstance(val, dict):
                val = json.dumps(val)
            row.append(val)
        rows.append(row)

    print(tabulate(rows, headers=columns, tablefmt="grid"))
    if len(result) > max_rows:
        print(f"\n...and {len(result) - max_rows} more rows.")

def load_docs():
    docs_dir = "docs"
    doc_files = [
        "MITRE ATT&CK API & Bash Automation Part 1.md",
        "MITRE ATT&CK API & Bash Automation Part 2.md",
        "MITRE ATT&CK API & Bash Automation Part 3.md",
    ]
    all_docs = []
    for fname in doc_files:
        fpath = os.path.join(docs_dir, fname)
        if os.path.exists(fpath):
            with open(fpath, "r") as f:
                all_docs.append(f.read())
    return "\n\n".join(all_docs)

def main():
    # --- NEW: load documentation at runtime
    docs_text = load_docs()
    combined_system_prompt = docs_text + "\n\n" + system_prompt

    print(Fore.CYAN + Style.BRIGHT + "\n=== MITRE ATT&CK Human-in-the-Loop ===")
    print(Style.DIM + "Type your natural language query. Type 'exit' to quit.\n")

    conversation_num = 1
    while True:
        print(Fore.YELLOW + f"\n[Question {conversation_num}]")
        user_query = input(Fore.GREEN + Style.BRIGHT + " User: " + Style.NORMAL)
        if user_query.strip().lower() in ("exit", "quit"):
            print(Fore.CYAN + Style.BRIGHT + "\nSession ended. Goodbye!\n")
            break

        # --- Inject combined docs and system prompt for every GPT call
        messages = [
            {"role": "system", "content": combined_system_prompt},
            {"role": "user", "content": user_query}
        ]

        print(Fore.MAGENTA + Style.BRIGHT + "\n Asking GPT for API suggestion...")
        response = openai.ChatCompletion.create(
            model="gpt-4.1",
            messages=messages, 
            temperature=0.35
        )
        gpt_reply = response['choices'][0]['message']['content']
        print(Fore.WHITE + Style.BRIGHT + "\n GPT suggestion:\n" + Style.NORMAL + gpt_reply.strip())

        # Look for a bash code block
        m = re.search(r"```bash(.*?)(?:```|$)", gpt_reply, re.DOTALL)
        if not m:
            print(Fore.RED + Style.BRIGHT + "\n No bash script found in GPT's reply.\n")
            conversation_num += 1
            continue

        script = m.group(1).strip()

        # Extract explanation after the code block (if any)
        explanation = ""
        explain_match = re.search(r"EXPLANATION\s*:\s*(.*)", gpt_reply, re.DOTALL | re.IGNORECASE)
        if explain_match:
            explanation = explain_match.group(1).strip()

        print(Fore.YELLOW + Style.BRIGHT + f"\n  Running bash script...\n")
        stdout, stderr = run_shell_script_inline(script)
        print(Fore.CYAN + Style.BRIGHT + "\n Script output:\n" + Style.NORMAL)
        print(stdout)
        if stderr:
            print(Fore.RED + Style.BRIGHT + "\n[stderr]\n" + stderr)
        if explanation:
            print(Fore.BLUE + Style.BRIGHT + "\n EXPLANATION:\n" + Style.NORMAL + explanation)
        print(Fore.LIGHTBLACK_EX + "\n" + "="*60 + "\n")
        conversation_num += 1

if __name__ == "__main__":
    main()

