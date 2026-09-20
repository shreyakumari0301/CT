"""FlashRank reranking audit over the saved field-aware TAA top-10 pool."""
import csv,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT))
RUN=ROOT/'eval_results/controlled_benchmark/taa20_20260918/fresh_full50_20260918T053944Z'
PROFILES=json.loads((ROOT/'eval_results/controlled_benchmark/taa20_20260918/actor_retrieval_study_v2/actor_profiles.json').read_text())
REPORTS=list(csv.DictReader((ROOT/'data/cti-taa.tsv').open(encoding='utf-8'),delimiter='\t'))
LABELS=list(csv.DictReader((ROOT/'data/ctibench_taa/cti-taa-responses.tsv').open(encoding='utf-8'),delimiter='\t'))
OUT=ROOT/'eval_results/controlled_benchmark/full/taa_flashrank_audit'; OUT.mkdir(parents=True,exist_ok=True)
def main():
 from flashrank import Ranker, RerankRequest
 from eval.taa_protocol import benchmark_alias_match
 ranker=Ranker(cache_dir=str(OUT/'models')); by={p['canonical_actor']:p for p in PROFILES}; rows=[]
 for idx,(report,label) in enumerate(zip(REPORTS,LABELS)):
  item=json.loads((RUN/'items'/f'taa-{idx}.json').read_text())
  names=(item.get('retrieval') or {}).get('multiquery_exact',[])[:10]; passages=[]
  for j,name in enumerate(names):
   p=by.get(name,{})
   text='Actor: '+name+'\n'+p.get('profile_text','')+'\n'+'\n'.join(f'{k}: '+', '.join(map(str,p.get(k,[]))) for k in ('aliases','malware','tools','techniques','campaigns','target_regions','target_sectors','infrastructure'))
   passages.append({'id':name,'text':text,'meta':{'base_rank':j+1}})
  ranked=ranker.rerank(RerankRequest(query=report['Text'],passages=passages)); names2=[x['id'] for x in ranked]
  rank=next((i for i,a in enumerate(names2,1) if benchmark_alias_match(a,label['GT'])),None)
  rows.append({'id':f'taa-{idx}','gold':label['GT'],'rank':rank,'ranking':names2})
 ranks=[r['rank'] for r in rows]; metrics={f'Recall@{k}':sum(bool(x and x<=k) for x in ranks)/len(ranks) for k in (1,3,5,10)}; metrics['MRR@10']=sum(1/x if x and x<=10 else 0 for x in ranks)/len(ranks)
 summary={'n':len(rows),'reranker':'FlashRank default ONNX reranker','metrics':metrics,'rows':rows,'note':'Reranks the existing field-aware top-10 pool; no candidate expansion or GPT calls.'}
 (OUT/'summary.json').write_text(json.dumps(summary,indent=2)); print(json.dumps(summary,indent=2))
if __name__=='__main__': main()
