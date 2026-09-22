"""Gold-blind ingestion of actor-linked MITRE ATT&CK STIX evidence.

The ingestion layer deliberately consumes source relationships rather than the
benchmark labels.  It materializes natural passages for groups, campaigns, and
software that MITRE links to a group, while retaining stable ATT&CK/STIX actor
identifiers and aliases for downstream retrieval and audit.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path


def clean_text(text: str) -> str:
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text or "")
    return re.sub(r"\s+", " ", text).strip()


def stable_unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def attack_external_id(obj: dict) -> str | None:
    return next(
        (
            reference.get("external_id")
            for reference in obj.get("external_references", [])
            if reference.get("source_name") == "mitre-attack" and reference.get("external_id")
        ),
        None,
    )


def _passage(actor: dict, source_type: str, source: dict, relationship: dict | None = None) -> dict:
    """Represent one natural ATT&CK source object as an actor-linked passage."""
    title = {"group": "ATT&CK group", "campaign": "ATT&CK campaign", "software": "ATT&CK software"}[source_type]
    description = clean_text(source.get("description", ""))
    relationship_text = clean_text((relationship or {}).get("description", ""))
    aliases = ", ".join(actor["aliases"])
    lines = [
        f"Actor: {actor['actor']}",
        f"Actor ATT&CK ID: {actor.get('attack_id') or 'unavailable'}",
        f"Actor aliases: {aliases}",
        f"{title}: {source['name']}",
    ]
    source_id = attack_external_id(source)
    if source_id:
        lines.append(f"{title} ID: {source_id}")
    if description:
        lines.append(f"Description: {description}")
    if relationship_text:
        lines.append(f"Actor-linked ATT&CK relationship evidence: {relationship_text}")
    text = "\n".join(lines)
    return {
        "actor": actor["actor"],
        "actor_stix_id": actor["stix_id"],
        "actor_attack_id": actor.get("attack_id"),
        "actor_aliases": actor["aliases"],
        "source_type": source_type,
        "source_stix_id": source["id"],
        "source_attack_id": source_id,
        "source_name": source["name"],
        "relationship_stix_id": (relationship or {}).get("id"),
        "text": text,
    }


def build_attack_multisource_corpus(bundle_path: str | Path) -> tuple[list[dict], dict]:
    """Return actor-linked group/campaign/software passages and a manifest.

    Campaigns are linked only through ATT&CK ``attributed-to`` relationships.
    Software is linked through direct group ``uses`` relationships or through a
    campaign already attributed to the group.  This prevents unsupported
    inference from a generic software description to an actor.
    """
    raw = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    objects = {
        obj["id"]: obj
        for obj in raw["objects"]
        if not obj.get("revoked") and not obj.get("x_mitre_deprecated") and obj.get("id")
    }
    groups = {key: obj for key, obj in objects.items() if obj["type"] == "intrusion-set"}
    actors = {
        key: {
            "actor": obj["name"],
            "stix_id": key,
            "attack_id": attack_external_id(obj),
            "aliases": stable_unique([obj["name"], *obj.get("aliases", [])]),
            "object": obj,
        }
        for key, obj in groups.items()
    }
    campaign_to_actor: dict[str, list[tuple[str, dict]]] = defaultdict(list)
    group_software: dict[str, list[tuple[dict, dict]]] = defaultdict(list)
    campaign_software: dict[str, list[tuple[dict, dict]]] = defaultdict(list)
    for relationship in objects.values():
        if relationship["type"] != "relationship":
            continue
        source = objects.get(relationship.get("source_ref"))
        target = objects.get(relationship.get("target_ref"))
        if not source or not target:
            continue
        if relationship.get("relationship_type") == "attributed-to":
            if source["type"] == "campaign" and target["id"] in actors:
                campaign_to_actor[source["id"]].append((target["id"], relationship))
            elif target["type"] == "campaign" and source["id"] in actors:
                campaign_to_actor[target["id"]].append((source["id"], relationship))
        if relationship.get("relationship_type") == "uses" and target["type"] in {"malware", "tool"}:
            if source["id"] in actors:
                group_software[source["id"]].append((target, relationship))
            elif source["type"] == "campaign":
                campaign_software[source["id"]].append((target, relationship))

    passages: list[dict] = []
    for actor_id, actor in sorted(actors.items(), key=lambda item: item[1]["actor"].casefold()):
        passages.append(_passage(actor, "group", actor["object"]))
        for campaign_id, attribution in sorted(
            ((campaign_id, rel) for campaign_id, pairs in campaign_to_actor.items() for group_id, rel in pairs if group_id == actor_id),
            key=lambda item: objects[item[0]]["name"].casefold(),
        ):
            campaign = objects[campaign_id]
            passages.append(_passage(actor, "campaign", campaign, attribution))
            for software, relationship in campaign_software.get(campaign_id, []):
                passages.append(_passage(actor, "software", software, relationship))
        for software, relationship in sorted(group_software.get(actor_id, []), key=lambda item: item[0]["name"].casefold()):
            passages.append(_passage(actor, "software", software, relationship))

    deduplicated: list[dict] = []
    seen: set[str] = set()
    for passage in passages:
        key = hashlib.sha256(
            (passage["actor_stix_id"] + "\0" + passage["source_stix_id"] + "\0" + passage["text"]).encode("utf-8")
        ).hexdigest()
        if key not in seen:
            seen.add(key)
            deduplicated.append(passage)
    source_counts = defaultdict(int)
    for passage in deduplicated:
        source_counts[passage["source_type"]] += 1
    alias_to_actor = {}
    for actor in actors.values():
        for alias in actor["aliases"]:
            alias_to_actor.setdefault(alias.casefold(), actor["actor"])
    manifest = {
        "bundle": str(bundle_path),
        "actors": len(actors),
        "passages": len(deduplicated),
        "passages_by_source_type": dict(sorted(source_counts.items())),
        "alias_keys": len(alias_to_actor),
        "unsupported_sources": {
            "CAPEC": "not present in the local ATT&CK STIX bundle; omitted rather than inferred",
            "Sigma": "not present in the local ATT&CK STIX bundle; omitted rather than inferred",
        },
        "corpus_sha256": hashlib.sha256(
            json.dumps(deduplicated, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }
    return deduplicated, manifest
