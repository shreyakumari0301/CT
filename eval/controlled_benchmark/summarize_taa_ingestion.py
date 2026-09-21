"""Validate and summarize the completed offline ingestion ablation."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from eval.taa_protocol import benchmark_alias_match

OUT = ROOT/'eval_results/controlled_benchmark/full/taa_ingestion_ablation'


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def main():
    summary = load(OUT/'summary.json')
    assert summary.get('complete'), 'Wait for all ingestion variants to finish.'
    baseline = load(OUT/'profile_lists_dense_bm25_rrf_rows.json')
    names = {p['canonical_actor'] for p in load(ROOT/'eval_results/controlled_benchmark/taa20_20260918/actor_retrieval_study_v2/actor_profiles.json')}
    frozen_base = ROOT/'eval_results/controlled_benchmark/full/taa_external_protocol'
    cta = {r['id']: r for r in load(frozen_base/'ctibench_frozen_retrieval/ft_idf_rrf_summary.json')['rows']}
    bm25 = {r['id']: r for r in load(frozen_base/'offline_diagnostics/passage_bm25_summary.json')['rows']}
    pools = {key: list(dict.fromkeys(cta[key]['ranking'][:10]+bm25[key]['bm25'][:20])) for key in cta}
    covered = {row['id'] for row in baseline if any(benchmark_alias_match(n,row['gold']) for n in pools[row['id']])}
    comparisons = {}
    lines = ['# Offline TAA ingestion ablation results', '',
             '50 reports; fixed actor inventory, cached off-the-shelf MiniLM, report-derived queries and retrieval scoring. No Qwen or GPT calls.', '',
             '## MiniLM + BM25 rank fusion', '',
             '| Ingestion variant | R@1 | R@3 | R@5 | R@10 | R@20 | MRR@10 |',
             '|---|---:|---:|---:|---:|---:|---:|']
    for variant, value in summary['variants'].items():
        for method in value['metrics']:
            rows = load(OUT/f'{variant}_{method}_rows.json')
            assert len(rows) == 50 and len({r['id'] for r in rows}) == 50
            for row in rows:
                assert len(row['ranking']) == len(set(row['ranking']))
                assert set(row['ranking']) <= names
                expected = next((i for i,n in enumerate(row['ranking'],1) if benchmark_alias_match(n,row['gold'])),None)
                assert expected == row['rank']
            scores = value['metrics'][method]['rank']
            assert all(scores[f'R@{a}'] <= scores[f'R@{b}'] for a,b in [(1,3),(3,5),(5,10),(10,20),(20,40)])
        m = value['metrics']['dense_bm25_rrf']['rank']
        lines.append('| '+variant+' | '+' | '.join(f'{m[f"R@{k}"]:.0%}' for k in (1,3,5,10,20))+f' | {m["MRR@10"]:.4f} |')
        rows = load(OUT/f'{variant}_dense_bm25_rrf_rows.json')
        changes = {}
        for k in (3,10,20):
            good = {r['id'] for r in rows if r['rank'] and r['rank']<=k}
            old = {r['id'] for r in baseline if r['rank'] and r['rank']<=k}
            changes[f'top{k}'] = {'gains':sorted(good-old),'losses':sorted(old-good)}
        # Explicitly a second candidate-expansion analysis, not a reranking gain.
        expanded = {r['id']:list(dict.fromkeys(pools[r['id']]+r['ranking'][:20])) for r in rows}
        new_covered = {r['id'] for r in rows if any(benchmark_alias_match(n,r['gold']) for n in expanded[r['id']])}
        (OUT/f'{variant}_expanded_pools.json').write_text(json.dumps([
            {'id':r['id'], 'gold':r['gold'], 'original_pool':pools[r['id']],
             'added_branch_top20':r['ranking'][:20], 'expanded_pool':expanded[r['id']],
             'covered':r['id'] in new_covered}
            for r in rows],indent=2),encoding='utf-8')
        comparisons[variant] = {'changes_vs_control':changes,'expanded_pool_coverage':len(new_covered)/50,
                                'new_covered_items':sorted(new_covered-covered),
                                'mean_expanded_pool':sum(map(len,expanded.values()))/50}
    # Same words, different boundaries: lexical ranking must remain identical.
    assert load(OUT/'procedures_fixed_bm25_rows.json') == load(OUT/'procedures_sentences_bm25_rows.json')
    lines += ['', '## Strict canonical identity sensitivity', '',
              '| Variant | Strict R@3 | Strict R@10 |', '|---|---:|---:|']
    for variant,value in summary['variants'].items():
        m = value['metrics']['dense_bm25_rrf']['strict_rank']
        lines.append(f'| {variant} | {m["R@3"]:.0%} | {m["R@10"]:.0%} |')
    lines += ['', '## Separate candidate expansion diagnostic', '',
              f'The local frozen CTA top-10 + shared BM25 top-20 pool covers {len(covered)}/50 under the local benchmark-compatible scorer. The supplied remote report records 41/50; input/scorer parity has not been established, so these coverage results are not directly comparable.', '',
              'Each row below appends the new hybrid top-20 to that pool. Coverage alone does not establish better top-3 ranking.', '',
              '| Added ingestion branch | Pool coverage | Newly covered reports | Mean candidates |',
              '|---|---:|---:|---:|']
    for v,c in comparisons.items():
        lines.append(f'| {v} | {c["expanded_pool_coverage"]:.0%} | {len(c["new_covered_items"])} | {c["mean_expanded_pool"]:.2f} |')
    lines += ['', '## Scope', '',
              'These experiments change ingestion within a fixed new retrieval harness. They do not reproduce the earlier fine-tuned MiniLM/IDF system and must not be read as changes from its headline metrics.', '',
              'All rankings are development-set results. Expanded software descriptions are background context, not evidence that an actor used every listed capability. Source-linked additions and input hashes are saved beside the results. Strict canonical metrics are available in summary.json.', '']
    (OUT/'comparison.json').write_text(json.dumps({'frozen_pool_coverage':len(covered)/50,'variants':comparisons},indent=2),encoding='utf-8')
    (OUT/'REPORT.md').write_text('\n'.join(lines),encoding='utf-8')
    print('\n'.join(lines))


if __name__ == '__main__':
    main()
