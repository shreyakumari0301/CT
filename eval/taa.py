"""CTIBench TAA loading, tagged answers, and alias/related-group scoring."""

import csv
import pickle
import re
from functools import lru_cache
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "ctibench_taa"


def attach_taa_labels(rows, labels_path=None):
    with open(labels_path or DATA_DIR / "cti-taa-responses.tsv", encoding="utf-8", newline="") as stream:
        labels = list(csv.DictReader(stream, delimiter="\t"))
    if len(rows) != len(labels):
        raise ValueError("TAA reports and positional labels must have identical counts")
    if any(not (label.get("GT") or "").strip() for label in labels):
        raise ValueError("TAA labels contain an empty ground truth")
    return [dict(row, GT=label["GT"].strip()) for row, label in zip(rows, labels)]


def parse_taa_answer_strict(raw):
    matches = re.findall(r"<ThreatActor>\s*([^<>]*?)\s*</ThreatActor>", raw or "", re.I | re.S)
    if len(matches) != 1:
        return None
    actor = " ".join(matches[0].split())
    return actor or None


def parse_taa_answer(raw):
    from eval.taa_protocol import extract_actor
    return extract_actor(raw)["extracted"]


def normalize_graph(mapping):
    graph = {}
    for actor, neighbors in mapping.items():
        actor = actor.strip().lower()
        for neighbor in neighbors:
            neighbor = neighbor.strip().lower()
            graph.setdefault(actor, set()).add(neighbor)
            graph.setdefault(neighbor, set()).add(actor)
    return graph


@lru_cache(maxsize=1)
def actor_graphs():
    graphs = []
    for name in ("alias_dict.pickle", "related_dict.pickle"):
        with (DATA_DIR / name).open("rb") as stream:
            graphs.append(normalize_graph(pickle.load(stream)))
    return tuple(graphs)


def connected(source, target, *graphs):
    pending = [source]
    visited = set()
    while pending:
        actor = pending.pop()
        if actor == target:
            return True
        if actor in visited:
            continue
        visited.add(actor)
        for graph in graphs:
            pending.extend(graph.get(actor, set()) - visited)
    return False


def score_taa(predictions, golds):
    if len(predictions) != len(golds):
        raise ValueError("TAA predictions and labels must align")
    aliases, related = actor_graphs()
    correct = plausible = 0
    for prediction, gold in zip(predictions, golds):
        if not gold:
            raise ValueError("Missing TAA ground truth")
        if not prediction:
            continue
        prediction, gold = prediction.strip().lower(), gold.strip().lower()
        if connected(prediction, gold, aliases):
            correct += 1
        elif connected(prediction, gold, aliases, related):
            plausible += 1
    count = len(golds)
    return {
        "n_scored": count,
        "n_correct": correct,
        "n_plausible_only": plausible,
        "n_incorrect": count - correct - plausible,
        "correct_acc": correct / count if count else None,
        "plausible_acc": (correct + plausible) / count if count else None,
    }
