# To run: uvicorn main:app --reload

from fastapi import FastAPI, Body, Query
from fastapi.responses import JSONResponse
from typing import List, Dict, Any, Optional
from pymongo import MongoClient
import os
import json



MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.getenv("DB_NAME", "mitre_attack")
client = MongoClient(MONGO_URI)
db = client[DB_NAME]

app = FastAPI(title="MITRE ATT&CK API", version="0.3.0")


@app.middleware("http")
async def pretty_print_json_response(request, call_next):
    response = await call_next(request)
    if response.headers.get("content-type", "").startswith("application/json"):
        # Decode and pretty print the response body
        body = [section async for section in response.body_iterator]
        body_bytes = b"".join(body)
        try:
            data = json.loads(body_bytes)
            pretty_body = json.dumps(data, indent=2, ensure_ascii=False)
            return JSONResponse(
                content=json.loads(pretty_body),
                media_type="application/json"
            )
        except Exception:
            # In case it's not JSON, just return the original
            return response
    return response


# Map MongoDB collection to friendly entity type
COLLECTION_TO_ENTITY = {
    "intrusion_sets": "groups",
    "attack_patterns": "techniques",
    "malware": "malware",
    "tools": "tools",
    "mitigations": "mitigations",
    "campaigns": "campaigns"
}
ENTITY_COLLECTION = {v: k for k, v in COLLECTION_TO_ENTITY.items()}

def stix_type(stix_id):
    return stix_id.split("--")[0] if "--" in stix_id else stix_id

# --- Dynamic discovery endpoints ---


@app.get("/api/v1/schema")
def get_schema():
    """Return available fields for each entity/collection, including one level down for nested objects/arrays."""
    schema = {}
    for entity, collection_name in ENTITY_COLLECTION.items():
        fields = set()
        subfields = set()
        for doc in db[collection_name].find({}, projection={"_id": 0}).limit(100):
            for k, v in doc.items():
                fields.add(k)
                # For dicts: add subfields as k.subkey
                if isinstance(v, dict):
                    for sk in v.keys():
                        subfields.add(f"{k}.{sk}")
                # For lists of dicts: add subfields as k.subkey
                elif isinstance(v, list) and v and isinstance(v[0], dict):
                    for sk in v[0].keys():
                        subfields.add(f"{k}.{sk}")
        allfields = sorted(fields) + sorted(subfields)
        schema[entity] = allfields
    return schema


@app.get("/api/v1/{entity}/schema")
def get_entity_schema(entity: str):
    """Return available fields for a single entity/collection, including one level down."""
    if entity not in ENTITY_COLLECTION:
        return {"error": f"Entity '{entity}' not recognized."}
    fields = set()
    subfields = set()
    collection_name = ENTITY_COLLECTION[entity]
    for doc in db[collection_name].find({}, projection={"_id": 0}).limit(100):
        for k, v in doc.items():
            fields.add(k)
            if isinstance(v, dict):
                for sk in v.keys():
                    subfields.add(f"{k}.{sk}")
            elif isinstance(v, list) and v and isinstance(v[0], dict):
                for sk in v[0].keys():
                    subfields.add(f"{k}.{sk}")
    allfields = sorted(fields) + sorted(subfields)
    return {"entity": entity, "fields": allfields}


@app.get("/api/v1/{entity}/groupby")
def group_by_field(
    entity: str,
    field: str = Query(..., description="Field to group by (e.g. kill_chain_phases.phase_name)"),
    top: int = Query(5, description="Top N per group"),
    by: str = Query("groups", description="Sort/aggregate each group by this field (e.g. groups, malware, etc.)"),
    filters: Optional[str] = Query(None, description="JSON object as string of extra filters (optional)")
):
    """
    Group entities by a field, and for each group value, return top N entities sorted by 'by' metric.
    Example: /api/v1/techniques/groupby?field=kill_chain_phases.phase_name&top=5&by=groups
    """
    import json
    from pymongo import DESCENDING

    if entity not in ENTITY_COLLECTION:
        return {"error": f"Entity '{entity}' not recognized."}
    collection = db[ENTITY_COLLECTION[entity]]
    # Parse filters if provided
    filter_dict = json.loads(filters) if filters else {}

    # Support dot notation for subfields
    if "." in field:
        field_parts = field.split(".")
        def extract_field(doc):
            val = doc
            for part in field_parts:
                if isinstance(val, list):
                    # flatten all occurrences
                    val = [v.get(part) for v in val if isinstance(v, dict) and part in v]
                    # flatten one more level if needed
                    if len(val) == 1 and isinstance(val[0], list):
                        val = val[0]
                elif isinstance(val, dict) and part in val:
                    val = val[part]
                else:
                    val = None
            return val
    else:
        def extract_field(doc):
            return doc.get(field)

    # Load and group entities
    cursor = collection.find(filter_dict, {"_id": 0})
    group_map = {}
    for doc in cursor:
        group_vals = extract_field(doc)
        if isinstance(group_vals, list):
            for gval in group_vals:
                if gval is not None:
                    group_map.setdefault(gval, []).append(doc)
        elif group_vals is not None:
            group_map.setdefault(group_vals, []).append(doc)

    # Sort and trim per group
    result = {}
    for gval, docs in group_map.items():
        if by and by != "name":
            # Example: by=groups means sort by how many groups use the technique
            if by == "groups" and entity == "techniques":
                # Compute for each technique how many groups use it
                id_to_count = {}
                for d in docs:
                    tid = d.get("id")
                    count = db["relationships"].count_documents({
                        "relationship_type": "uses",
                        "target_ref": tid,
                        "source_ref": {"$regex": "^intrusion-set"}
                    })
                    id_to_count[tid] = count
                sorted_docs = sorted(docs, key=lambda d: id_to_count.get(d["id"], 0), reverse=True)
            else:
                sorted_docs = sorted(docs, key=lambda d: d.get(by, ""), reverse=True)
        else:
            sorted_docs = sorted(docs, key=lambda d: d.get("name", ""))
        result[gval] = sorted_docs[:top]
    return result

@app.get("/api/v1/search")
def search_entities(
    q: str = Query(..., description="Free-text search term"),
    entity: Optional[str] = Query(None, description="Restrict to entity type (optional)"),
    filter_by: Optional[List[str]] = Query(None, description="Additional filters, e.g. filter_by=x_mitre_domains:enterprise-attack")
):
    import re
    regex = re.compile(q, re.IGNORECASE)
    all_types = ["groups", "techniques", "malware", "tools", "mitigations", "campaigns"]
    result = []
    search_types = [entity] if entity in all_types else all_types

    # Parse extra filters
    filters = {}
    if filter_by:
        for f in filter_by:
            if ":" in f:
                k, v = f.split(":", 1)
                filters[k] = v

    for typ in search_types:
        coll = db[ENTITY_COLLECTION[typ]]
        or_query = [
            {"description": regex},
            {"name": regex},
            {"aliases": regex},
        ]
        # Add extra filters with AND
        query = {"$and": [filters] if filters else []}
        query["$and"].append({"$or": or_query})
        cursor = coll.find(query, {"_id": 0})
        for doc in cursor:
            doc["entity_type"] = typ
            result.append(doc)
    return result


@app.get("/api/v1/entities")
def list_entities():
    """Dynamically list available entity types from MongoDB."""
    collections = db.list_collection_names()
    exclude = ("relationships", "system.indexes")
    entities = [COLLECTION_TO_ENTITY.get(col, col) for col in collections if col not in exclude]
    return {"entities": sorted(entities)}


@app.get("/api/v1/relationships")
def get_relationships(
    type: str = Query(None, description="Filter by relationship type (e.g. 'uses', 'mitigates', etc.)"),
    source: str = Query(None, description="Filter by source_ref STIX ID"),
    target: str = Query(None, description="Filter by target_ref STIX ID"),
    full: bool = Query(False, description="If true, return all relationship objects")
):
    collection = db["relationships"]
    # Only list types if no other filter is given
    if not (type or source or target or full):
        rels = collection.distinct("relationship_type")
        return {"relationship_types": rels}
    query = {}
    if type:
        query["relationship_type"] = type
    if source:
        query["source_ref"] = source
    if target:
        query["target_ref"] = target
    rels = list(collection.find(query, {"_id": 0}))
    return rels


@app.get("/api/v1/relationship_endpoints")
def relationship_source_target_map():
    """List source/target STIX types for each relationship type."""
    pipeline = [
        {
            "$group": {
                "_id": {
                    "relationship_type": "$relationship_type",
                    "source_type": {"$substr": ["$source_ref", 0, {"$indexOfBytes": ["$source_ref", "--"]}]},
                    "target_type": {"$substr": ["$target_ref", 0, {"$indexOfBytes": ["$target_ref", "--"]}]},
                }
            }
        }
    ]
    rels = db["relationships"].aggregate(pipeline)
    mapping = {}
    for rel in rels:
        key = rel["_id"]["relationship_type"]
        mapping.setdefault(key, []).append({
            "source_type": rel["_id"]["source_type"],
            "target_type": rel["_id"]["target_type"]
        })
    return mapping

# --- N-chain flexible query endpoint (POST) ---

def get_top_entities(entity: str, by: str, top: int, filters: Dict = None) -> List[Dict]:
    collection = db[ENTITY_COLLECTION[entity]]
    filters = filters or {}
    if by == "name":
        return list(collection.find(filters, {"_id": 0}).sort("name", 1).limit(top))
    elif by == "recent":
        return list(collection.find(filters, {"_id": 0}).sort("created", -1).limit(top))
    elif by == "techniques" and entity == "groups":
        pipeline = [
            {"$match": {"relationship_type": "uses", "source_ref": {"$regex": "^intrusion-set"}}},
            {"$group": {"_id": "$source_ref", "technique_count": {"$sum": 1}}},
            {"$sort": {"technique_count": -1}},
            {"$limit": top},
            {"$lookup": {"from": "intrusion_sets", "localField": "_id", "foreignField": "id", "as": "group"}},
            {"$unwind": "$group"},
            {"$replaceRoot": {"newRoot": {"$mergeObjects": ["$group", {"technique_count": "$technique_count"}]}}}
        ]
        return list(db["relationships"].aggregate(pipeline))
    else:
        return list(collection.find({}, {"_id": 0}).sort("name", 1).limit(top))

def get_related_entities(source_ids: List[str], relationship: str, target_entity: str, top: Optional[int] = None) -> List[str]:
    target_collection = ENTITY_COLLECTION[target_entity]
    relationship_docs = list(
        db["relationships"].find({
            "relationship_type": relationship,
            "source_ref": {"$in": source_ids},
            "target_ref": {"$regex": f"^{db[target_collection].name[:-1]}"}
        })
    )
    target_ids = [rel["target_ref"] for rel in relationship_docs]
    if top:
        target_ids = target_ids[:top]
    return target_ids

def get_entities_by_ids(entity: str, ids: List[str]) -> List[Dict]:
    collection = db[ENTITY_COLLECTION[entity]]
    return list(collection.find({"id": {"$in": ids}}, {"_id": 0}))

@app.post("/api/v1/query")
def n_chain_query(chain: List[Dict[str, Any]] = Body(..., example=[
    {"entity": "groups", "selection": "top5", "by": "techniques"},
    {"relationship": "uses", "entity": "techniques", "selection": "top10"},
    {"relationship": "uses", "entity": "malware", "selection": "top3"}
])):
    """Flexible N-chain traversal for ATT&CK."""
    step_entities = {}
    # Step 1: get initial IDs
    first = chain[0]
    entity = first["entity"]
    selection = first.get("selection")
    by = first.get("by", "name")
    filters = first.get("filters", {})
    top = int(selection.replace("top", "")) if selection and selection.startswith("top") else None

    entities = get_top_entities(entity, by, top, filters) if top else db[ENTITY_COLLECTION[entity]].find(filters, {"_id": 0})
    ids = [e["id"] for e in entities]
    step_entities[entity] = entities

    # Chain: Traverse relationships
    for step in chain[1:]:
        rel = step["relationship"]
        target_entity = step["entity"]
        selection = step.get("selection")
        top = int(selection.replace("top", "")) if selection and selection.startswith("top") else None

        ids = get_related_entities(ids, rel, target_entity, top=top)
        step_entities[target_entity] = get_entities_by_ids(target_entity, ids)

    return {
        "result": step_entities[chain[-1]['entity']],
        "intermediate": step_entities
    }

# --- Generic RESTful endpoints ---

from fastapi import Request

@app.get("/api/v1/{entity}")
async def get_all(
    entity: str,
    request: Request,
    top: Optional[int] = Query(None, description="Return top N entities"),
    by: Optional[str] = Query("name", description="Sort or aggregate by (name, recent, etc.)")
):
    """
    Get all entities, with optional sorting/aggregation and flexible filters.
    Filter any field by passing ?filter_by=field:value (multiple allowed).
    """
    if entity not in ENTITY_COLLECTION:
        return {"error": f"Entity '{entity}' not recognized."}
    collection = db[ENTITY_COLLECTION[entity]]

    # --- Parse filters from repeated filter_by params ---
    filters = {}
    for k, v in request.query_params.multi_items():
        if k == "filter_by":
            if ":" in v:
                field, value = v.split(":", 1)
                mongo_ops = {">=": "$gte", "<=": "$lte", ">": "$gt", "<": "$lt", "!=": "$ne"}
                for op_str, mongo_op in mongo_ops.items():
                    if value.startswith(op_str):
                        comp_value = value[len(op_str):]
                        # Merge operators for the same field
                        if field not in filters or not isinstance(filters[field], dict):
                            filters[field] = {}
                        filters[field][mongo_op] = comp_value
                        break
                else:
                    filters[field] = value


    cursor = collection.find(filters, {"_id": 0})

    if by == "recent":
        cursor = cursor.sort("created", -1)
    elif by and by != "name":
        cursor = cursor.sort(by, -1)
    else:
        cursor = cursor.sort("name", 1)
    if top:
        cursor = cursor.limit(top)
    return list(cursor)


@app.get("/api/v1/{entity}/{entity_id}")
def get_by_id(entity: str, entity_id: str):
    """Get an entity by its ID."""
    if entity not in ENTITY_COLLECTION:
        return {"error": f"Entity '{entity}' not recognized."}
    collection = db[ENTITY_COLLECTION[entity]]
    doc = collection.find_one({"id": entity_id}, {"_id": 0})
    return doc or {"error": f"Entity '{entity}' with id '{entity_id}' not found."}

@app.get("/api/v1/{entity}/{entity_id}/{relationship}")
def get_related(
    entity: str,
    entity_id: str,
    relationship: str,
    target: Optional[str] = Query(None, description="Target entity type to filter results (optional)"),
    top: Optional[int] = Query(None, description="Limit number of results (optional)")
):
    """
    Generic traversal: from one entity, follow a relationship to related entities.
    """
    if entity not in ENTITY_COLLECTION:
        return {"error": f"Entity '{entity}' not recognized."}
    if target and target not in ENTITY_COLLECTION:
        return {"error": f"Target entity '{target}' not recognized."}
    rel_query = {
        "relationship_type": relationship,
        "source_ref": entity_id
    }
    if target:
        rel_query["target_ref"] = {"$regex": f"^{db[ENTITY_COLLECTION[target]].name[:-1]}"}
    rel_docs = db["relationships"].find(rel_query)
    target_ids = [doc["target_ref"] for doc in rel_docs]
    if top:
        target_ids = target_ids[:top]
    # Merge results from all possible collections if target is None
    results = []
    collections_to_search = [ENTITY_COLLECTION[target]] if target else ENTITY_COLLECTION.values()
    for col in collections_to_search:
        results.extend(list(db[col].find({"id": {"$in": target_ids}}, {"_id": 0})))
    return results

@app.get("/")
def root():
    return {"message": "MITRE ATT&CK API is running"}


