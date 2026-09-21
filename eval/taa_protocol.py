"""Versioned conservative TAA extraction; independent of gold labels."""
import json
import re
import unicodedata
from functools import lru_cache
from pathlib import Path

ALIAS_PATH = Path(__file__).resolve().parents[1] / "data/ctibench_taa/actor_aliases.v2.json"
PARSER_VERSION = "taa-parser-v2"

def normalize_name(value):
    return " ".join(re.findall(r"\w+", unicodedata.normalize("NFKC", value).casefold().replace("_", " ")))

@lru_cache(maxsize=1)
def dictionary():
    data = json.loads(ALIAS_PATH.read_text(encoding="utf-8"))
    index = {}
    for entity in data["entities"]:
        for name in [entity["canonical"]] + entity["aliases"]:
            index.setdefault(normalize_name(name), set()).add(entity["canonical"])
    return data, index

def canonicalize(value):
    if not value:
        return None
    index = dictionary()[1]
    value = value.strip(" <>\n\t\"'`.*")
    matches = index.get(normalize_name(value), set())
    if matches:
        return next(iter(matches)) if len(matches) == 1 else None
    # A parenthetical name is accepted only if all parts resolve to one entity.
    parts = [x.strip() for x in re.split(r"[()]", value) if x.strip()]
    if len(parts) > 1:
        resolved = [index.get(normalize_name(x), set()) for x in parts]
        if all(len(x) == 1 for x in resolved) and len(set.union(*resolved)) == 1:
            return next(iter(resolved[0]))
    return None

def benchmark_alias_match(prediction, gold):
    """Preserve published acceptance, adding canonical spelling equivalence.

    The legacy benchmark accepts some subgroup relationships. This function
    preserves that policy without putting those relationships in the alias file.
    Exact-entity matching must be reported as a separate sensitivity metric.
    """
    from eval.taa import score_taa
    if not prediction:
        return False
    if score_taa([prediction], [gold])["n_correct"]:
        return True
    p, g = canonicalize(prediction), canonicalize(gold)
    return p is not None and g is not None and p == g

def known_mentions(raw):
    """Whole-name matching; ambiguous names remain unresolved."""
    index = dictionary()[1]
    text = " " + normalize_name(raw) + " "
    spans = []
    for alias, actors in index.items():
        if len(alias) < 3:
            continue
        for m in re.finditer(r"(?<!\w)" + re.escape(alias) + r"(?!\w)", text):
            spans.append((m.start(), m.end(), actors, raw))
    # Prefer a full alias to a shorter name contained inside it.
    spans = [x for x in spans if not any(y[0] <= x[0] and y[1] >= x[1] and y[1]-y[0] > x[1]-x[0] for y in spans)]
    actors = set()
    ambiguous = False
    for _, _, targets, _ in spans:
        actors.update(targets)
        ambiguous |= len(targets) != 1
    return actors, ambiguous

def extract_actor(raw):
    raw = (raw or "").strip()
    def result(value, method, status="valid"):
        canonical = canonicalize(value)
        return {"extracted": value, "canonical": canonical, "method": method,
                "status": status if canonical else "unknown_actor", "parser_version": PARSER_VERSION}
    def unresolved(reason):
        return {"extracted": None, "canonical": None, "method": reason,
                "status": "unresolved", "parser_version": PARSER_VERSION}
    tags = re.findall(r"<ThreatActor>\s*([^<>]+?)\s*</ThreatActor>", raw, re.I | re.S)
    fields = []
    for obj in re.findall(r"\{[^{}]*\}", raw, re.S):
        try:
            payload = json.loads(obj)
        except ValueError:
            continue
        for key in ("threat_actor", "actor", "final_actor"):
            if key in payload:
                if not isinstance(payload[key], str):
                    return unresolved("nonstring_actor")
                fields.append(payload[key])
    explicit = [x.strip() for x in tags + fields]
    if explicit:
        identities = {canonicalize(x) or normalize_name(x) for x in explicit}
        return result(explicit[0], "structured") if len(identities) == 1 else unresolved("conflicting_structured_answers")
    answers = re.findall(r"(?im)^\s*(?:final\s+(?:actor|answer)|threat\s+actor|answer)\s*:\s*([^\n]+)", raw)
    if answers:
        identities = {canonicalize(x) or normalize_name(x) for x in answers}
        return result(answers[-1], "explicit_final") if len(identities) == 1 else unresolved("conflicting_final_answers")
    if len(raw) <= 120 and canonicalize(raw):
        return result(raw.strip("<> "), "short_actor")
    # Do not turn a rejected candidate into a final selection.
    if re.search(r"\b(?:not|unlikely|ruled out|rather than|cannot determine|could be|either|uncertain)\b", raw, re.I):
        return unresolved("uncertain_or_rejected_candidate")
    actors, ambiguous = known_mentions(raw)
    if len(actors) == 1 and not ambiguous:
        return result(next(iter(actors)), "unique_known_actor")
    return unresolved("multiple_or_no_known_actors")
