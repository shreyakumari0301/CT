#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
PYTHONPATH=. python - <<'PY'
import json
from pathlib import Path
from collections import defaultdict

ROOT = Path('.')
BASE = ROOT / 'tcar' / 'eval_results'
EVAL = ROOT / 'eval_results'
CC = ROOT / 'CTICONNECT benchmark' / 'eval_results'

def mean(xs):
    xs = [float(x) for x in xs if x is not None]
    return sum(xs)/len(xs) if xs else None

def pct(x):
    return f"{100*x:.1f}%" if isinstance(x, float) else "—"

def load_cf(path):
    by = {}
    if not path.exists():
        return []
    for line in path.open(encoding='utf-8', errors='replace'):
        try:
            r = json.loads(line)
        except Exception:
            continue
        rid = r.get('id') or f"{r.get('task')}-{r.get('idx')}"
        prev = by.get(str(rid))
        if prev is None or (prev.get('error') and not r.get('error')):
            by[str(rid)] = r
        elif bool(prev.get('error')) == bool(r.get('error')):
            by[str(rid)] = r
    return [r for r in by.values() if not r.get('error')]

def score_cf(path):
    rows = load_cf(path)
    cb = [1.0 if r.get('closed_book_correct') else 0.0 for r in rows if 'closed_book_correct' in r]
    rag = [1.0 if r.get('retrieval_correct') else 0.0 for r in rows if 'retrieval_correct' in r]
    return len(rows), mean(cb), mean(rag)

def score_baseline(path, tasks=None):
    by = defaultdict(list)
    if not path.exists():
        return {}
    from eval.scoring import (
        parse_mcq_answer, parse_cwe_answer, parse_ate_ids, parse_gold_ate, instance_macro_f1,
        parse_cvss_vector, mad_cvss_base_score,
    )
    for line in path.open(encoding='utf-8', errors='replace'):
        try:
            r = json.loads(line)
        except Exception:
            continue
        task = r.get('task')
        if tasks and task not in tasks:
            continue
        gold = r.get('gold')
        parsed = r.get('parsed')
        raw = r.get('raw') or ''
        if task == 'mcq':
            pred = parsed if parsed in {'A','B','C','D'} else parse_mcq_answer(str(raw))
            by[task].append(1.0 if pred and str(pred).upper()==str(gold).upper() else 0.0)
        elif task == 'rcm':
            pred = parsed or parse_cwe_answer(str(raw))
            g = parse_cwe_answer(str(gold)) if gold else None
            by[task].append(1.0 if pred and g and str(pred).upper()==str(g).upper() else 0.0)
        elif task == 'ate':
            pred = parsed if isinstance(parsed, list) else parse_ate_ids(str(raw))
            g = gold if isinstance(gold, list) else parse_gold_ate(str(gold or ''))
            by[task].append(instance_macro_f1(pred or [], g or []))
        elif task == 'vsp':
            pred = parsed or parse_cvss_vector(str(raw))
            # store pair later; for now mark presence via exact if possible
            by[task].append(1.0 if pred and gold and str(pred).replace(' ','')==str(gold).replace(' ','') else 0.0)
    return {t: (len(v), mean(v)) for t,v in by.items()}

def score_cta_jsonl(path, task_key_field='task'):
    """Score CTA E2E / Connect jsonl if present."""
    by = defaultdict(list)
    if not path.exists():
        return {}
    for line in path.open(encoding='utf-8', errors='replace'):
        try:
            r = json.loads(line)
        except Exception:
            continue
        task = r.get(task_key_field) or r.get('task_key') or '?'
        # common fields
        if 'correct' in r:
            by[task].append(1.0 if r['correct'] else 0.0)
        elif 'score' in r and isinstance(r['score'], (int, float)):
            by[task].append(float(r['score']))
        elif 'metrics' in r and isinstance(r['metrics'], dict):
            m = r['metrics']
            if 'correct' in m:
                by[task].append(1.0 if m['correct'] else 0.0)
            elif 'f1' in m:
                by[task].append(float(m['f1']))
            elif 'acc' in m:
                by[task].append(float(m['acc']))
    return {t: (len(v), mean(v)) for t,v in by.items()}

# ---- Soft GAD / Forced RAG
print('=== CF Soft GAD + Forced RAG (sol) ===')
soft_stamp = '20260906Tgpt56sol_soft_gad_cb'
soft_cc = '20260906Tgpt56sol_soft_gad_cc'
forced = '20260904Tgpt56sol_forced_rag_cb'
forced_cc = '20260906Tgpt56sol_forced_rag_cc'

rows = []
for label, stamp, tasks in [
    ('SoftGAD', soft_stamp, ['ate','rcm','mcq','vsp']),
    ('ForcedRAG', forced, ['ate','rcm','mcq','vsp']),
]:
    for t in tasks:
        p = BASE / f'counterfactual_ctibench_{t}_{stamp}.jsonl'
        n, cb, rag = score_cf(p)
        rows.append((label, f'CTIBench/{t}', n, cb, rag))

for label, stamp, tasks in [
    ('SoftGAD', soft_cc, ['rcm','ata']),
    ('ForcedRAG', forced_cc, ['rcm','ata']),
]:
    for t in tasks:
        p = BASE / f'counterfactual_cticonnect_{t}_{stamp}.jsonl'
        n, cb, rag = score_cf(p)
        rows.append((label, f'Connect/{t}', n, cb, rag))

print(f"{'System':<10} {'Task':<16} {'n':>5} {'CB':>8} {'Retrieve':>10}")
for sys, task, n, cb, rag in rows:
    print(f"{sys:<10} {task:<16} {n:>5} {pct(cb):>8} {pct(rag):>10}")

# ---- Baselines
print('\n=== Paper baselines (sol, partial OK) ===')
bases = [
    ('Self-RAG', EVAL/'selfrag_20260906Tgpt56sol_baselines.jsonl'),
    ('Adaptive', EVAL/'adaptive_rag_20260906Tgpt56sol_baselines.jsonl'),
    ('GraphRAG-edge', EVAL/'graphrag_edge_20260906Tgpt56sol_baselines.jsonl'),
    ('TAdaRAG', EVAL/'tadarag_20260906Tgpt56sol_baselines.jsonl'),
    ('Unified', EVAL/'unified_rag_20260906Tgpt56sol_baselines.jsonl'),
]
# also find unified variants
for p in sorted(EVAL.glob('*20260906Tgpt56sol*')):
    if p.suffix=='.jsonl' and any(x in p.name for x in ('unified','selfrag','adaptive','graphrag','tadarag')):
        pass

print(f"{'System':<14} {'task':<6} {'n':>5} {'score':>8}")
for name, path in bases:
    sc = score_baseline(path)
    if not sc:
        # try alternate unified names
        alts = list(EVAL.glob(f'*{name.split()[0].lower()}*20260906Tgpt56sol*.jsonl'))
        if alts:
            path = alts[0]
            sc = score_baseline(path)
    if not sc:
        print(f"{name:<14} {'—':<6} {'0':>5} {'missing':>8} ({path.name if path else ''})")
        continue
    for t,(n,s) in sorted(sc.items()):
        print(f"{name:<14} {t:<6} {n:>5} {pct(s):>8}")

# ---- CTA E2E
print('\n=== CTA-RAG full E2E (not CF ablation) ===')
# CTIBench oracle/router summaries
found=False
for p in sorted(EVAL.glob('*_summary.json'), key=lambda x: x.stat().st_mtime, reverse=True):
    if ('oracle' in p.name or 'router' in p.name) and '202609' in p.name:
        d=json.loads(p.read_text(encoding='utf-8'))
        print(f"CTIBench {p.name}: metric={d.get('metric')} score={d.get('score')} n={d.get('n')} route={d.get('route_mode') or d.get('routing_accuracy')}")
        found=True
if not found:
    print('CTIBench CTA oracle/router (sol): NOT FINISHED / cleared by WSL restart')
    # show turbo refs if useful
    for p in [
        EVAL/'mcq_router_20260813T175714Z_summary.json',
        EVAL/'rcm_router_20260813T193651Z_summary.json',
        EVAL/'vsp_router_20260815T101149Z_summary.json',
        EVAL/'ate_router_20260813T223256Z_summary.json',
        EVAL/'rcm_oracle_20260904T085524Z_summary.json',
    ]:
        if p.exists():
            d=json.loads(p.read_text(encoding='utf-8'))
            print(f"  turbo/ref {p.name}: score={d.get('score')} n={d.get('n')} metric={d.get('metric')}")

# Connect CTA port
port = CC/'cticonnect_cta_rag_port_20260906Tgpt56sol_cta_port.jsonl'
print('\nConnect cta_rag_port sol:')
if port.exists():
    n=sum(1 for _ in port.open(encoding='utf-8', errors='replace'))
    # score if possible
    by=defaultdict(list)
    sample=None
    for line in port.open(encoding='utf-8', errors='replace'):
        try: r=json.loads(line)
        except: continue
        if sample is None: sample=r
        task=r.get('task') or '?'
        if 'correct' in r:
            by[task].append(1.0 if r['correct'] else 0.0)
        elif isinstance(r.get('score'), (int,float)):
            by[task].append(float(r['score']))
        elif isinstance(r.get('f1'), (int,float)):
            by[task].append(float(r['f1']))
    print(f'  lines={n}/450 sample_keys={list(sample.keys())[:20] if sample else None}')
    for t,v in sorted(by.items()):
        print(f'  {t}: n={len(v)} score={pct(mean(v))}')
else:
    print('  missing (cleared / not restarted)')

# Connect baseline systems
print('\nConnect baselines stamp 20260906Tgpt56sol_baselines:')
for p in sorted(CC.glob('cticonnect_*20260906Tgpt56sol_baselines*.jsonl')):
    n=sum(1 for _ in p.open(encoding='utf-8', errors='replace'))
    print(f'  {p.name}: lines={n}')

# TAA
print('\n=== TAA (non-gated) ===')
for mode in ['closed_book','cta']:
    p=EVAL/f'taa_{mode if mode!="closed_book" else "closedbook"}_20260906Tgpt56sol_soft_gad_taa_{mode if mode!="closed_book" else "closed_book"}_summary.json'
    # actual names from earlier
    pass
for p in sorted(EVAL.glob('taa_*20260906Tgpt56sol_soft_gad*_summary.json')):
    d=json.loads(p.read_text(encoding='utf-8'))
    print(f"{p.name}: Correct={pct(d.get('correct_acc'))} Plausible={pct(d.get('plausible_acc'))} n={d.get('n_scored')}")

# running?
print('\n=== Still running ===')
import subprocess
out=subprocess.getoutput("pgrep -af 'soft_gad|run_ctibench|run_taa|baselines|cta_rag_port' || true")
print(out[:2000] if out else 'none')
PY
