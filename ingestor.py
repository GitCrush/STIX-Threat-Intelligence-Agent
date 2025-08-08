import os
import re
import json
from pymongo import MongoClient
from stix2 import parse

# Configuration
DATA_DIR = "attack-stix-data"
DOMAINS = {
    "enterprise": "enterprise-attack",
    "mobile": "mobile-attack",
    "ics": "ics-attack"
}
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "mitre_attack"

# --- GENERIC: Use dynamic collection naming ---
def stix_type_to_collection(stix_type):
    # e.g. "attack-pattern" -> "attack_patterns"
    return stix_type.replace("-", "_") + "s"

def find_latest_json(domain_folder):
    files = os.listdir(domain_folder)
    versioned = []
    pattern = re.compile(r'(\d+)\.(\d+)')
    for fname in files:
        if fname.endswith('.json') and '-' in fname:
            m = pattern.findall(fname)
            if m:
                version = tuple(map(int, m[-1]))
                versioned.append((version, fname))
    if not versioned:
        return None
    versioned.sort(reverse=True)
    return os.path.join(domain_folder, versioned[0][1])

def ingest_stix_json(filepath, db):
    print(f"Ingesting: {filepath}")
    with open(filepath) as f:
        bundle = parse(f.read(), allow_custom=True)
    stats = {}
    for obj in getattr(bundle, 'objects', []):   # Handle only valid STIX objects
        stix_type = obj.get('type')
        if stix_type:
            collection_name = stix_type_to_collection(stix_type)
            collection = db[collection_name]
            collection.replace_one({"id": obj['id']}, obj, upsert=True)
            stats[collection_name] = stats.get(collection_name, 0) + 1
    print(f"Ingested counts: {stats}")

def main():
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    for domain, folder in DOMAINS.items():
        domain_folder = os.path.join(DATA_DIR, folder)
        latest_json = find_latest_json(domain_folder)
        if latest_json:
            ingest_stix_json(latest_json, db)
        else:
            print(f"No JSON file found for {domain}")

if __name__ == "__main__":
    main()
