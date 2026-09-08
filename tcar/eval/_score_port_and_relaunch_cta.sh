#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
source .venv/bin/activate
PYTHONPATH=. python - <<'PY'
import json
from pathlib import Path
from collections import defaultdict
from eval.cticonnect_metrics import score_id_item

CC = Path('CTICONNECT benchmark/eval_results')
port = CC/'cticonnect_cta_rag_port_20260906Tgpt56sol_cta_port.jsonl'
by=defaultdict(list)
if port.exists():
    for line in port.open(encoding='utf-8', errors='replace'):
        try: r=json.loads(line)
        except: continue
        task=r.get('task')
        gold=r.get('ground_truth') or r.get('gold')
        pred=r.get('prediction') or r.get('parsed') or r.get('raw')
        if task in {'rcm','ata'} and gold is not None:
            try:
                s=score_id_item(task, pred, gold)
            except Exception as e:
                continue
            # s may be dict with exact/f1
            if isinstance(s, dict):
                by[task].append(s)
            else:
                by[task].append({'exact': float(s)})
    for t, rows in by.items():
        n=len(rows)
        exact=sum(r.get('exact',0) for r in rows)/n if n else None
        f1s=[r['f1'] for r in rows if 'f1' in r]
        f1=sum(f1s)/len(f1s) if f1s else None
        print(f'cta_rag_port {t}: n={n} exact={exact} f1={f1}')
else:
    print('no port file')

# turbo CTA router refs
EVAL=Path('eval_results')
print('\nTurbo CTA router refs:')
for name in ['mcq_router_20260813T175714Z_summary.json','rcm_router_20260813T193651Z_summary.json','vsp_router_20260815T101149Z_summary.json','ate_router_20260813T223256Z_summary.json']:
    p=EVAL/name
    if p.exists():
        d=json.loads(p.read_text())
        print(name, d.get('metric'), d.get('score'), 'n=', d.get('n'))

# Connect baseline systems counts
print('\nConnect baseline files:')
for p in sorted(CC.glob('cticonnect_*gpt56sol*'))[:20]:
    n=sum(1 for _ in p.open(encoding='utf-8', errors='replace')) if p.suffix=='.jsonl' else '-'
    print(n, p.name)
PY

# Relaunch CTA E2E sol (cleared by WSL restart) — oracle+router priority ATE/RCM then Connect
nohup env MODE=both TASKS=ate,rcm,mcq,vsp WORKERS=1 CONNECT_STAMP=20260907Tgpt56sol_cta_port \
  bash tcar/eval/run_gpt56sol_cta_e2e.sh \
  > tcar/eval_results/logs/cta_e2e_relaunch_nohup.out 2>&1 &
echo cta_relaunch_pid=$!
sleep 3
pgrep -af 'run_ctibench|cta_rag_port' | head -15 || true
