"""Label-blind fixed-budget fusion of saved TAA retrieval rankings.

No weights are fitted. Every variant emits exactly 20 unique actors. Prediction
artifacts are written before labels are read by the evaluation stage.
"""
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
BASE = ROOT / 'eval_results/controlled_benchmark/full'
OUT = BASE / 'taa_fixed_top20_fusion'
INPUTS = {
    'cta': BASE/'taa_external_protocol/ctibench_frozen_retrieval/ft_idf_rrf_summary.json',
    'bm25': BASE/'taa_external_protocol/offline_diagnostics/passage_bm25_summary.json',
    'procedure': BASE/'taa_ingestion_ablation/procedures_fixed_dense_bm25_rrf_rows.json',
    'enriched': BASE/'taa_ingestion_ablation/source_enriched_sentences_dense_bm25_rrf_rows.json',
}
METHODS = {
    'existing_order_top20': ('cta', 'bm25'),
    'existing_rrf_top20': ('cta', 'bm25'),
    'procedure_rrf_top20': ('cta', 'bm25', 'procedure'),
    'enriched_rrf_top20': ('cta', 'bm25', 'enriched'),
}


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def save(path, data):
    path.write_text(json.dumps(data, indent=2), encoding='utf-8')


def fuse(branches, budget=20, constant=60):
    scores, evidence = defaultdict(float), defaultdict(dict)
    for branch, names in branches.items():
        assert len(names) == len(set(names))
        for rank, name in enumerate(names, 1):
            scores[name] += 1.0/(constant+rank)
            evidence[name][branch] = rank
    ranked = sorted(scores, key=lambda name: (-scores[name], name))
    assert len(ranked) >= budget
    return ranked[:budget], [
        {'actor': n, 'rrf_score': scores[n], 'branch_ranks': evidence[n]}
        for n in ranked
    ]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    # Strip all label/metric fields at the input boundary.
    rankings = {}
    for name, path in INPUTS.items():
        raw = load(path)
        rows = raw['rows'] if isinstance(raw, dict) else raw
        key = 'bm25' if name == 'bm25' else 'ranking'
        limit = 10 if name == 'cta' else 20
        rankings[name] = {r['id']: r[key][:limit] for r in rows}
        assert len(rankings[name]) == 50
    ids = sorted(rankings['cta'], key=lambda x: int(x.split('-')[-1]))
    assert all(set(r) == set(ids) for r in rankings.values())
    manifest = {
        'n': 50, 'budget': 20, 'rrf_constant': 60, 'branch_weights': 'all 1',
        'branch_cutoffs': {'cta': 10, 'bm25': 20, 'procedure': 20, 'enriched': 20},
        'methods': METHODS, 'generation_calls': 0, 'training_or_parameter_search': False,
        'hashes': {name: hashlib.sha256(path.read_bytes()).hexdigest() for name,path in INPUTS.items()},
        'code_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    save(OUT/'manifest.json', manifest)
    predictions = {}
    for method, sources in METHODS.items():
        rows = []
        for item_id in ids:
            branches = {name: rankings[name][item_id] for name in sources}
            if method == 'existing_order_top20':
                pool = list(dict.fromkeys(branches['cta'] + branches['bm25']))
                selected, trace = pool[:20], []
            else:
                selected, trace = fuse(branches)
                pool = [x['actor'] for x in trace]
            assert len(selected) == len(set(selected)) == 20
            assert set(selected) <= set().union(*map(set,branches.values()))
            rows.append({'id': item_id, 'top20': selected, 'branches': branches,
                         'candidate_pool': pool, 'rrf_trace': trace})
        predictions[method] = rows
        save(OUT/f'{method}_predictions.json', rows)

    # Ranking is now complete. Labels are used only below this boundary.
    from eval.taa_protocol import benchmark_alias_match, canonicalize, normalize_name
    labels = {r['id']:r['gold'] for r in load(INPUTS['cta'])['rows']}
    for name in ('procedure', 'enriched'):
        assert all(r['gold'].strip() == labels[r['id']].strip() for r in load(INPUTS[name]))
    result = {'n': 50, 'budget': 20, 'methods': {}, 'complete': True,
              'scope': 'Development-set offline retrieval. Fixed equal-weight RRF, no Qwen, no label-selected candidates. Local scorer; not directly comparable to remote 82% pool until parity is established.'}
    baseline_success = set()
    for method, rows in predictions.items():
        evaluated = []
        for row in rows:
            gold = labels[row['id']]
            match = lambda n: benchmark_alias_match(n, gold)
            identity = lambda n: canonicalize(n) or normalize_name(n)
            rank = next((j for j,n in enumerate(row['top20'],1) if match(n)), None)
            strict = next((j for j,n in enumerate(row['top20'],1) if identity(n)==identity(gold)), None)
            evaluated.append({'id':row['id'],'gold':gold,'rank':rank,'strict_rank':strict,
                              'pool_covered':any(match(n) for n in row['candidate_pool'])})
        metrics = {}
        for field in ('rank', 'strict_rank'):
            rs = [r[field] for r in evaluated]
            metrics[field] = {f'R@{k}':sum(r is not None and r<=k for r in rs)/50 for k in (1,3,5,10,20)}
            metrics[field]['MRR@10'] = sum(1/r if r and r<=10 else 0 for r in rs)/50
        success = {r['id'] for r in evaluated if r['rank'] is not None}
        if method == 'existing_order_top20':
            baseline_success = success
        result['methods'][method] = {
            'metrics': metrics, 'correct_top20':len(success),
            'mean_pool_size':sum(len(r['candidate_pool']) for r in rows)/50,
            'pool_coverage':sum(r['pool_covered'] for r in evaluated)/50,
            'gains_vs_existing':sorted(success-baseline_success),
            'losses_vs_existing':sorted(baseline_success-success),
        }
        save(OUT/f'{method}_evaluation.json', evaluated)
    save(OUT/'summary.json',result)
    lines = ['# Fixed top-20 TAA retrieval fusion', '', result['scope'], '',
             '| Method | R@1 | R@3 | R@5 | R@10 | R@20 | Correct / 50 | Strict R@20 |',
             '|---|---:|---:|---:|---:|---:|---:|---:|']
    for method,row in result['methods'].items():
        m = row['metrics']['rank']
        lines.append('| '+method+' | '+' | '.join(f'{m[f"R@{k}"]:.0%}' for k in (1,3,5,10,20))+
                     f' | {row["correct_top20"]}/50 | {row["metrics"]["strict_rank"]["R@20"]:.0%} |')
    lines += ['', 'All methods return exactly 20 unique actors. RRF uses 1/(60+rank) with equal branch weights and actor-name tie breaking. No weight sweep or gold-based inclusion is performed.', '',
              'The procedure and enriched branches already contain MiniLM/BM25 fusion; their evidence is correlated with the shared BM25 branch. This is a fixed branch-fusion experiment, not proof of independent evidence.', '']
    (OUT/'REPORT.md').write_text('\n'.join(lines),encoding='utf-8')
    print('\n'.join(lines))


if __name__ == '__main__':
    main()
