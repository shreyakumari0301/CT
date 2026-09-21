import json,sys,csv
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
BASE=ROOT/'eval_results/controlled_benchmark/full/taa_external_protocol/offline_diagnostics'
CTA=json.loads((ROOT/'eval_results/controlled_benchmark/full/taa_external_protocol/ctibench_frozen_retrieval/ft_idf_rrf_summary.json').read_text())['rows']; SHARED=json.loads((BASE/'passage_bm25_summary.json').read_text())['rows']; PROFILES=json.loads((ROOT/'eval_results/controlled_benchmark/taa20_20260918/actor_retrieval_study_v2/actor_profiles.json').read_text()); OUT=ROOT/'eval_results/controlled_benchmark/full/taa_qwen3_union_audit';OUT.mkdir(parents=True,exist_ok=True)
REPORTS={f'taa-{i}':r['Text'] for i,r in enumerate(csv.DictReader((ROOT/'data/cti-taa.tsv').open(encoding='utf-8'),delimiter='\t'))}
def main():
 from sentence_transformers import CrossEncoder
 from eval.taa_protocol import benchmark_alias_match
 by={p['canonical_actor']:p for p in PROFILES}; model=CrossEncoder('Qwen/Qwen3-Reranker-0.6B',max_length=2048,device='cuda'); checkpoint=OUT/'checkpoint.json'; rows=json.loads(checkpoint.read_text()) if checkpoint.exists() else []; done={r['id'] for r in rows}
 for x,y in zip(CTA,SHARED):
  if x['id'] in done: continue
  pool=list(dict.fromkeys(x['ranking'][:20]+y['bm25'][:20])); passages=[]
  for name in pool:
   p=by.get(name,{}); passages.append('Actor: '+name+'\n'+p.get('profile_text','')+'\n'+'\n'.join(f'{k}: '+', '.join(map(str,p.get(k,[]))) for k in ('aliases','malware','tools','techniques','campaigns','target_regions','target_sectors','infrastructure')))
  scores=model.predict([(REPORTS[x['id']],p) for p in passages],show_progress_bar=False,batch_size=32); names=[n for _,n in sorted(zip(scores,pool),reverse=True)]; r=next((i for i,n in enumerate(names,1) if benchmark_alias_match(n,x['gold'])),None); rows.append({'id':x['id'],'gold':x['gold'],'rank':r})
  checkpoint.write_text(json.dumps(rows,indent=2))
 rs=[z['rank'] for z in rows]; metrics={f'Recall@{k}':sum(bool(r and r<=k) for r in rs)/len(rs) for k in (1,3,5,10,20)};metrics['MRR@10']=sum(1/r if r and r<=10 else 0 for r in rs)/len(rs); (OUT/'summary.json').write_text(json.dumps({'model':'Qwen/Qwen3-Reranker-0.6B','metrics':metrics,'n':len(rows),'complete':len(rows)==50},indent=2));print(json.dumps(metrics,indent=2))
if __name__=='__main__':main()
