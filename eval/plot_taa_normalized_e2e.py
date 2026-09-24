"""Plot normalized TAA retrieval coverage and OpenAI E2E attribution results."""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt

from eval.taa_protocol import benchmark_alias_match

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "eval_results/controlled_benchmark/full/taa_normalized_e2e_openai"


def main() -> None:
    summary = json.loads((RESULTS / "summary.json").read_text(encoding="utf-8"))
    rows = json.loads((RESULTS / "checkpoint.json").read_text(encoding="utf-8"))
    cutoffs = (1, 3, 5, 10, 20)
    recall = [
        sum(any(benchmark_alias_match(entry["actor"], row["gold"]) for entry in row["normalized_ranking"][:cutoff]) for row in rows) / len(rows)
        for cutoff in cutoffs
    ]
    funnel_labels = ("CTA/BM25\nunion", "Frozen\ntop-20", "OpenAI\nselection")
    funnel_values = (summary["candidate_pool_coverage"], summary["frozen_top20_coverage"], summary["openai_accuracy"])
    colors = ("#2f6f9f", "#4f8f8b", "#d97742")

    fig, axes = plt.subplots(1, 2, figsize=(10.5, 4.4), gridspec_kw={"width_ratios": (1.35, 1)})
    axes[0].plot(cutoffs, recall, marker="o", linewidth=2.4, color=colors[0])
    axes[0].set_xticks(cutoffs)
    axes[0].set_ylim(0, 1)
    axes[0].set_xlabel("Normalized ranking cutoff")
    axes[0].set_ylabel("Canonical recall")
    axes[0].set_title("Normalized retrieval")
    axes[0].grid(axis="y", alpha=0.25)
    for cutoff, value in zip(cutoffs, recall):
        axes[0].annotate(f"{value:.0%}", (cutoff, value), xytext=(0, 8), textcoords="offset points", ha="center", fontsize=8)

    axes[1].bar(funnel_labels, funnel_values, color=colors, width=0.62)
    axes[1].set_ylim(0, 1)
    axes[1].set_ylabel("Canonical coverage / accuracy")
    axes[1].set_title("End-to-end attribution")
    axes[1].grid(axis="y", alpha=0.25)
    for index, value in enumerate(funnel_values):
        axes[1].text(index, value + 0.03, f"{value:.0%}", ha="center", fontsize=9)

    fig.suptitle("Normalized CTA15 + BM2525 TAA with OpenAI selection", fontsize=12)
    fig.tight_layout()
    for suffix, options in (("png", {"dpi": 220}), ("pdf", {}), ("svg", {})):
        fig.savefig(RESULTS / f"normalized_e2e_results.{suffix}", bbox_inches="tight", **options)
    metrics = {"normalized_recall": dict(zip((f"R@{cutoff}" for cutoff in cutoffs), recall)), "funnel": dict(zip(("union_coverage", "top20_coverage", "openai_accuracy"), funnel_values))}
    (RESULTS / "plot_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(RESULTS / "normalized_e2e_results.png")


if __name__ == "__main__":
    main()