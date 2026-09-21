"""Controlled, offline ingestion ablation. No Qwen, generation, or web calls.

Only document construction changes. Gold labels are accessed after rankings
are fixed. New evidence comes from the local STIX snapshot, not test reports.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import re
import sys
import time
from collections import Counter
from pathlib import Path

os.environ['HF_HUB_OFFLINE'] = '1'
os.environ['TRANSFORMERS_OFFLINE'] = '1'
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
OUT = ROOT / 'eval_results/controlled_benchmark/full/taa_ingestion_ablation'
PROFILE_PATH = ROOT / 'eval_results/controlled_benchmark/taa20_20260918/actor_retrieval_study_v2/actor_profiles.json'
STIX_PATH = ROOT / 'data/ctibench_taa/enterprise-attack.json'
VARIANTS = ('profile_lists', 'procedures_fixed', 'procedures_sentences',
            'source_enriched_sentences', 'normalized_enriched_sentences')
NORMALIZATIONS = {
    'usa': 'United States', 'u.s.': 'United States', 'uk': 'United Kingdom',
    'u.k.': 'United Kingdom', 'south-east asia': 'Southeast Asia',
    'south east asia': 'Southeast Asia', 'defence': 'defense',
    'telecom': 'telecommunications', 'telecoms': 'telecommunications',
    'banking': 'financial', 'health care': 'healthcare',
}


def save(path, data):
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(data, indent=2), encoding='utf-8')
    temp.replace(path)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_additions(profiles):
    from utils.taa_actor_retrieval import clean
    objects = {o['id']: o for o in json.loads(STIX_PATH.read_text(encoding='utf-8'))['objects']
               if not o.get('revoked') and not o.get('x_mitre_deprecated')}
    known = {p['canonical_actor'] for p in profiles}
    additions = {name: [] for name in known}
    for rel in objects.values():
        if rel['type'] != 'relationship':
            continue
        src, dst = objects.get(rel.get('source_ref')), objects.get(rel.get('target_ref'))
        if not src or not dst:
            continue
        actor, evidence = None, None
        if (src['type'] == 'intrusion-set' and dst['type'] in ('malware', 'tool')
                and rel.get('relationship_type') == 'uses'):
            actor, evidence = src, dst
        elif (src['type'] == 'campaign' and dst['type'] == 'intrusion-set'
              and rel.get('relationship_type') == 'attributed-to'):
            actor, evidence = dst, src
        if actor is None or actor['name'] not in known:
            continue
        text = clean(evidence.get('description', '')).strip()
        if not text:
            continue
        # Software capabilities are explicitly background, not a claim that the
        # actor performed every capability described for this shared software.
        qualifier = 'Associated campaign' if evidence['type'] == 'campaign' else 'Associated software background'
        additions[actor['name']].append({
            'text': f"{qualifier}: {evidence['name']}. {text}",
            'source_id': evidence['id'], 'relationship_id': rel['id'],
            'modified': evidence.get('modified'),
            'source_references': evidence.get('external_references', []),
        })
    return additions


def base_text(profile):
    fields = ('aliases', 'malware', 'tools', 'techniques', 'campaigns',
              'target_regions', 'target_sectors', 'infrastructure')
    return '\n'.join([profile['profile_text']] +
                     [f"{k}: " + '; '.join(profile[k]) for k in fields if profile[k]])


def normalized(text):
    # Preserve original evidence and append only vocabulary-backed equivalents.
    expansions = [v for k, v in NORMALIZATIONS.items()
                  if re.search(r'(?<!\w)' + re.escape(k) + r'(?!\w)', text, re.I)]
    return text + ('\nNormalized terminology: ' + '; '.join(sorted(set(expansions))) if expansions else '')


def chunks(text, tokenizer, sentence_aware, budget=180):
    if not sentence_aware:
        tokens = tokenizer.encode(text, add_special_tokens=False, verbose=False)
        return [tokenizer.decode(tokens[i:i+budget], skip_special_tokens=True)
                for i in range(0, len(tokens), budget)]
    result, current = [], []
    for sentence in re.split(r'(?<=[.!?])\s+|\n+', text):
        tokens = tokenizer.encode(sentence.strip(), add_special_tokens=False, verbose=False)
        if not tokens:
            continue
        if current and len(current) + len(tokens) > budget:
            result.append(tokenizer.decode(current, skip_special_tokens=True))
            current = []
        while len(tokens) > budget:
            result.append(tokenizer.decode(tokens[:budget], skip_special_tokens=True))
            tokens = tokens[budget:]
        current += tokens
    if current:
        result.append(tokenizer.decode(current, skip_special_tokens=True))
    return result


def documents(profiles, additions, tokenizer, variant):
    docs, actor_texts = [], []
    for i, p in enumerate(profiles):
        if variant == 'profile_lists':
            sections = [('profile', base_text(p), p['source_id'])]
        else:
            sections = [('identity', base_text(p), p['source_id'])]
            sections += [('procedure', r['description'], r['source_id'])
                         for r in p['relationships'] if r['description'].strip()]
            if 'enriched' in variant:
                sections += [('source_background', r['text'], r['source_id'])
                             for r in additions[p['canonical_actor']]]
        raw_sections = [normalized(s[1]) if variant.startswith('normalized') else s[1] for s in sections]
        actor_texts.append(f"Actor: {p['canonical_actor']}. " + '\n'.join(dict.fromkeys(raw_sections)))
        seen = set()
        for field, text, source_id in sections:
            if variant.startswith('normalized'):
                text = normalized(text)
            for body in chunks(text, tokenizer, 'sentences' in variant):
                body = ' '.join(body.split())
                if not body or body in seen:
                    continue
                seen.add(body)
                # Identical prefix and total model limit for all variants.
                doc = f"Actor: {p['canonical_actor']}. {body}"
                assert len(tokenizer.encode(doc, add_special_tokens=True, verbose=False)) <= 256
                docs.append({'actor_index': i, 'field': field, 'source_id': source_id, 'text': doc})
    return docs, actor_texts


def lexical_scores(texts, reports):
    import numpy as np
    tokenize = lambda s: re.findall(r'[a-z0-9]+', s.casefold())
    counts = [Counter(tokenize(s)) for s in texts]
    df = Counter(term for c in counts for term in c)
    lengths = np.array([sum(c.values()) for c in counts])
    avg = lengths.mean()
    result = np.zeros((len(reports), len(texts)), dtype=np.float32)
    for ri, report in enumerate(reports):
        for term in set(tokenize(report)):
            freq = np.array([c.get(term, 0) for c in counts])
            idf = math.log(1 + (len(texts)-df[term]+0.5)/(df[term]+0.5))
            result[ri] += idf * freq * 2.5 / (freq + 1.5*(0.25+0.75*lengths/avg))
    return result


def evaluate(rankings, golds, names):
    from eval.taa_protocol import benchmark_alias_match, canonicalize, normalize_name
    records = []
    for i, (ranking, gold) in enumerate(zip(rankings, golds)):
        selected = [names[x] for x in ranking]
        strict = lambda n: (canonicalize(n) or normalize_name(n)) == (canonicalize(gold) or normalize_name(gold))
        records.append({'id': f'taa-{i}', 'gold': gold, 'ranking': selected,
                        'rank': next((j for j,n in enumerate(selected,1) if benchmark_alias_match(n,gold)), None),
                        'strict_rank': next((j for j,n in enumerate(selected,1) if strict(n)), None)})
    metrics = {}
    for key in ('rank', 'strict_rank'):
        ranks = [r[key] for r in records]
        metrics[key] = {f'R@{k}': sum(r is not None and r<=k for r in ranks)/len(ranks) for k in (1,3,5,10,20,40)}
        metrics[key]['MRR@10'] = sum(1/r if r and r<=10 else 0 for r in ranks)/len(ranks)
    return metrics, records


def main():
    import numpy as np
    import torch
    from sentence_transformers import SentenceTransformer
    from utils.taa_actor_retrieval import ActorRetriever
    torch.set_num_threads(4)
    OUT.mkdir(parents=True, exist_ok=True)
    profiles = json.loads(PROFILE_PATH.read_text(encoding='utf-8'))
    report_path = ROOT/'data/cti-taa.tsv'
    label_path = ROOT/'data/ctibench_taa/cti-taa-responses.tsv'
    with report_path.open(encoding='utf-8') as f:
        reports = [r['Text'] for r in csv.DictReader(f, delimiter='\t')]
    with label_path.open(encoding='utf-8') as f:
        golds = [r['GT'].strip() for r in csv.DictReader(f, delimiter='\t')]
    assert len(reports) == len(golds) == 50
    names = [p['canonical_actor'] for p in profiles]
    model = SentenceTransformer('all-MiniLM-L6-v2', local_files_only=True, device='cpu')
    model.max_seq_length = 256
    # Freeze existing report-only queries; no re-extraction with enriched data.
    helper = ActorRetriever.__new__(ActorRetriever)
    helper.model = model
    helper.vocab = {f: sorted({v for p in profiles for k in keys for v in p[k] if len(v)>=3}, key=lambda v:(-len(v),v))
                    for f, keys in {'malware_tools':['malware','tools'], 'aliases_campaigns':['aliases','campaigns'], 'infrastructure':['infrastructure']}.items()}
    queries = [list(helper.queries(r)[0].values()) for r in reports]
    for i,q in enumerate(queries):
        if not q:
            queries[i] = [model.tokenizer.decode(model.tokenizer.encode(reports[i],add_special_tokens=False,verbose=False)[:200])]
    qvectors = model.encode([q for qs in queries for q in qs], batch_size=32, normalize_embeddings=True)
    additions = source_additions(profiles)
    save(OUT/'source_additions.json', additions)
    save(OUT/'queries.json', queries)
    summary = {'n':50, 'actors':len(names), 'model':'all-MiniLM-L6-v2', 'generation_calls':0,
               'protocol':'Fixed report-only field queries; cosine max over chunks per actor/query; RRF k=60 across queries; actor BM25 k1=1.5 b=.75; equal RRF of dense and BM25 top40.',
               'hashes': {str(p.relative_to(ROOT)):digest(p) for p in (PROFILE_PATH,STIX_PATH,report_path,label_path,Path(__file__))},
               'source_additions':sum(map(len,additions.values())), 'variants':{},
               'caveat':'Development-set ablation. This is a controlled new retrieval harness, not a rerun of the remote Qwen or fine-tuned MiniLM baseline.'}
    vector_cache = {}
    for variant in VARIANTS:
        start = time.time()
        docs, actor_texts = documents(profiles, additions, model.tokenizer, variant)
        texts = [d['text'] for d in docs]
        missing = list(dict.fromkeys(t for t in texts if t not in vector_cache))
        print(f'{variant}: {len(docs)} chunks, {len(missing)} new embeddings', flush=True)
        for offset in range(0,len(missing),256):
            part = missing[offset:offset+256]
            vectors = model.encode(part, batch_size=32, normalize_embeddings=True)
            vector_cache.update(zip(part,vectors))
            if offset % 2048 == 0:
                print(f'  encoded {min(offset+256,len(missing))}/{len(missing)}',flush=True)
        embeddings = np.array([vector_cache[t] for t in texts])
        doc_actors = np.array([d['actor_index'] for d in docs])
        # BM25 uses deduplicated raw documents aggregated by actor; chunk overlap
        # cannot create artificial extra documents in its IDF computation.
        lexical = lexical_scores(actor_texts,reports)
        dense_rankings, lexical_rankings, fused_rankings = [], [], []
        cursor = 0
        for ri,qs in enumerate(queries):
            dense_rrf = np.zeros(len(names))
            for vec in qvectors[cursor:cursor+len(qs)]:
                scores = embeddings @ vec
                actor_scores = np.full(len(names),-np.inf)
                np.maximum.at(actor_scores,doc_actors,scores)
                order = sorted(range(len(names)),key=lambda i:(-actor_scores[i],names[i]))
                for rank,ai in enumerate(order,1):
                    dense_rrf[ai] += 1/(60+rank)
            cursor += len(qs)
            dense_order = sorted(range(len(names)),key=lambda i:(-dense_rrf[i],names[i]))
            bm_order = sorted(range(len(names)),key=lambda i:(-lexical[ri,i],names[i]))
            fused = Counter()
            for order in (dense_order[:40], bm_order[:40]):
                for rank,ai in enumerate(order,1):
                    fused[ai] += 1/(60+rank)
            dense_rankings.append(dense_order)
            lexical_rankings.append(bm_order)
            fused_rankings.append(sorted(fused,key=lambda i:(-fused[i],names[i])))
        metrics = {}
        for method,ranking in [('dense',dense_rankings),('bm25',lexical_rankings),('dense_bm25_rrf',fused_rankings)]:
            measured, records = evaluate(ranking,golds,names)
            metrics[method] = measured
            save(OUT/f'{variant}_{method}_rows.json',records)
            print(variant,method,json.dumps(measured['rank']),flush=True)
        save(OUT/f'{variant}_documents.json',docs)
        summary['variants'][variant] = {'chunks':len(docs),'elapsed_seconds':time.time()-start,'metrics':metrics}
        save(OUT/'summary.json',summary)
    summary['complete'] = True
    save(OUT/'summary.json',summary)
    print('COMPLETE',flush=True)


if __name__ == '__main__':
    main()
