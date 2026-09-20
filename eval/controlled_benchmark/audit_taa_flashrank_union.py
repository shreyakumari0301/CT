import json,sys,csv
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
BASE=ROOT/'eval_results/controlled_benchmark/full/taa_external_protocol/offline_diagnostics'
CTA=json.loads((ROOT/'eval_results/controlled_benchmark/full/taa_external_protocol/ctibench_frozen_retrieval/ft_idf_rrf_summary.json').read_text())['rows']
SHARED=json.loads((BASE/'passage_bm25_summary.json').read_text())['rows']
PROFILES=json.loads((ROOT/'eval_results/controlled_benchmark/taa20_20260918/actor_retrieval_study_v2/actor_profiles.json').read_text())
OUT=ROOT/'eval_results/controlled_benchmark/full/taa_flashrank_union_audit';OUT.mkdir(parents=True,exist_ok=True)
REPORTS={f'taa-{i}':r['Text'] for i,r in enumerate(csv.DictReader((ROOT/'data/cti-taa.tsv').open(encoding='utf-8'),delimiter='\t'))}
def main():
 from flashrank import Ranker,RerankRequest
 from eval.taa_protocol import benchmark_alias_match
 by={p['canonical_actor']:p for p in PROFILES}; results={}
 for model_name in ('ms-marco-MiniLM-L-12-v2','rank-T5-flan'):
  ranker=Ranker(model_name=model_name,cache_dir=str(OUT/'models')); rows=[]
  for x,y in zip(CTA,SHARED):
   pool=list(dict.fromkeys(x['ranking'][:20]+y['bm25'][:20])); passages=[]
   for name in pool:
    p=by.get(name,{})
    text='Actor: '+name+'\n'+p.get('profile_text','')+'\n'+'\n'.join(f'{k}: '+', '.join(map(str,p.get(k,[]))) for k in ('aliases','malware','tools','techniques','campaigns','target_regions','target_sectors','infrastructure'))
    passages.append({'id':name,'text':text})
   ranked=ranker.rerank(RerankRequest(query=REPORTS[x['id']],passages=passages)); names=[z['id'] for z in ranked]
   r=next((i for i,n in enumerate(names,1) if benchmark_alias_match(n,x['gold'])),None)
   rows.append({'id':x['id'],'gold':x['gold'],'rank':r,'pool_size':len(pool),'ranking':names})
  rs=[z['rank'] for z in rows]; metrics={f'Recall@{k}':sum(bool(r and r<=k) for r in rs)/len(rs) for k in (1,3,5,10,20)};metrics['MRR@10']=sum(1/r if r and r<=10 else 0 for r in rs)/len(rs)
  results[model_name]={'metrics':metrics,'rows':rows}
 summary={'n':50,'pool':'CTA top-20 union shared BM25 top-20 (84% oracle coverage)','models':results,'note':'FlashRank reranking audit; no GPT calls.'}
 (OUT/'summary_models.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary,indent=2))
if __name__=='__main__':main()
