"""Offline dense TAA representation ablation (no graph expansion, no GPT)."""
from __future__ import annotations
import csv, hashlib, json, sys
from collections import defaultdict
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT))
BASE=ROOT/'eval_results/controlled_benchmark/taa20_20260918'
OUT=ROOT/'eval_results/controlled_benchmark/full/taa_field_combination_audit'; OUT.mkdir(parents=True,exist_ok=True)
CONFIGS={
 'full_profile':['profile_text','malware_tools','infrastructure','targeting','behavior','aliases_campaigns'],
 'research_only':['behavior'],
 'research_expertise':['behavior','malware_tools'],
 'research_discussion':['behavior','targeting'],
 'behavior_targeting_identity':['behavior','targeting','aliases_campaigns'],
}
def metrics(rows):
 r=[x['rank'] for x in rows]; return {f'recall_at_{k}':sum(bool(v and v<=k) for v in r)/len(r) for k in (1,3,10)}|{'mrr_at_10':sum(1/v if v and v<=10 else 0 for v in r)/len(r)}
def main():
 import numpy as np
 from sentence_transformers import SentenceTransformer
 from eval.taa_protocol import benchmark_alias_match
 from utils.taa_actor_retrieval import ActorRetriever, FIELDS
 profiles=json.loads((BASE/'actor_retrieval_study_v2/actor_profiles.json').read_text())
 reports=list(csv.DictReader((ROOT/'data/cti-taa.tsv').open(encoding='utf-8'),delimiter='\t'))
 labels=list(csv.DictReader((ROOT/'data/ctibench_taa/cti-taa-responses.tsv').open(encoding='utf-8'),delimiter='\t'))
 model=SentenceTransformer('all-MiniLM-L6-v2'); model.max_seq_length=256
 # Reuse only the gold-blind query construction; avoid building the large
 # production FAISS index for this representation-only ablation.
 helper=ActorRetriever.__new__(ActorRetriever); helper.model=model
 helper.vocab={f:sorted({v for p in profiles for key in keys for v in p[key] if len(v)>=3},key=lambda x:(-len(x),x)) for f,keys in {
  'malware_tools':['malware','tools'],'aliases_campaigns':['aliases','campaigns'],'infrastructure':['infrastructure']}.items()}
 allrows={}; summaries={}
 for name,fields in CONFIGS.items():
  docs=[]
  for ai,p in enumerate(profiles):
   parts=[]
   for f in fields:
    text=(p.get('profile_text','') if f=='profile_text' else p.get('field_text',{}).get(f,''))
   if text.strip():
    ids=model.tokenizer.encode(text.strip(),add_special_tokens=False)[:180]
    text=model.tokenizer.decode(ids,skip_special_tokens=True)
   parts.append(f"Threat actor {p['canonical_actor']} {f}: {text}")
  combined='\n'.join(parts)
  ids=model.tokenizer.encode(combined,add_special_tokens=False)[:180]
  docs.append({'actor_index':ai,'actor':p['canonical_actor'],'text':model.tokenizer.decode(ids,skip_special_tokens=True)})
  emb=model.encode([d['text'] for d in docs],normalize_embeddings=True,batch_size=64,show_progress_bar=False)
  rows=[]
  for rr,ll in zip(reports,labels):
   qs,_=helper.queries(rr['Text']); qs['full']=' '.join(qs.values()) or rr['Text'][:2000]
   scores=defaultdict(lambda:defaultdict(float))
   qvecs=model.encode(list(qs.values()),normalize_embeddings=True,show_progress_bar=False)
   for qv in qvecs:
    vals=emb@qv
    for i in np.argsort(-vals)[:10]: scores[docs[int(i)]['actor']]['score']=max(scores[docs[int(i)]['actor']]['score'],float(vals[i]))
   ranked=[a for a,_ in sorted(((a,v['score']) for a,v in scores.items()),key=lambda x:(-x[1],x[0]))]
   rank=next((i for i,a in enumerate(ranked,1) if benchmark_alias_match(a,ll['GT'])),None)
   rows.append({'id':rr.get('ID') or rr.get('id'),'gold':ll['GT'],'rank':rank,'top10':ranked[:10]})
  allrows[name]=rows; summaries[name]={'fields':fields,'documents':len(docs),'metrics':metrics(rows),'absent_top10':sum(not x['rank'] or x['rank']>10 for x in rows)}
 (OUT/'field_combination_rows.json').write_text(json.dumps(allrows,indent=2),encoding='utf-8')
 summary={'configs':summaries,'note':'Dense representation ablation; same MiniLM, query extraction, dense retrieval and scoring; no graph traversal or GPT calls.','sha256':hashlib.sha256(json.dumps(CONFIGS,sort_keys=True).encode()).hexdigest()}
 (OUT/'field_combination_summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8'); print(json.dumps(summary,indent=2))
if __name__=='__main__': main()
