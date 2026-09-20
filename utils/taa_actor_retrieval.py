"""Gold-blind, local actor-field retrieval. No generation or evaluation labels."""
import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path

VERSION = "taa-actor-fields-rrf-v2"
FIELDS = ("malware_tools", "infrastructure", "targeting", "behavior", "aliases_campaigns")
REGIONS = ("South America", "Latin America", "Southeast Asia", "South Asia", "Middle East", "Europe", "Africa", "Colombia", "Myanmar", "Ukraine", "Poland", "Pakistan", "India", "China", "Japan", "South Korea", "North Korea", "United States", "Russia", "Turkey", "Lebanon")
SECTORS = ("government", "military", "financial", "bank", "energy", "manufacturing", "telecommunications", "healthcare", "education", "defense", "diplomatic", "technology")
BEHAVIORS = ("spearphishing", "phishing", "DLL side-loading", "DLL search order hijacking", "PowerShell", "scheduled task", "registry", "credential", "persistence", "process injection", "remote access", "command and control", "ransomware", "lateral movement")

def clean(text):
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text or "")
    return re.sub(r"\(Citation:[^)]*\)", "", text)

def contains(text, phrase):
    return len(phrase.strip()) >= 3 and re.search(r"(?<!\w)" + re.escape(phrase) + r"(?!\w)", text, re.I) is not None

def sentences(text):
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", clean(text)) if s.strip()]

def entity_mention(text, name, field):
    """Conservative lexical evidence: an ordinary word is not a named entity.

    Multiword names, mixed-case brands, IDs, and executable names have more
    distinctive surface forms. Plain single words additionally require a local
    entity cue and original capitalization. Domain suffixes never match names.
    """
    if not contains(text,name):return False
    if re.search(r'[\s\d._-]',name) or re.search(r'[a-z][A-Z]',name):
        return contains(text,name)
    cue = r'(?:actor|group|operation|campaign|named|called|tracked as|known as)' if field=='aliases_campaigns' else r'(?:malware|tool|trojan|backdoor|payload|ransomware|named|called|utility)'
    return bool(re.search(r'\b'+cue+r'\s+[\"\x27]?'+re.escape(name)+r'(?![\w.])',text) or
                re.search(r'(?<![\w.])'+re.escape(name)+r'[\"\x27]?\s+'+cue+r'\b',text))

def build_profiles(bundle_path):
    raw = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    objects = {o["id"]:o for o in raw["objects"] if not o.get("revoked") and not o.get("x_mitre_deprecated")}
    profiles = {}
    for key,o in objects.items():
        if o["type"] != "intrusion-set": continue
        refs = o.get("external_references", [])
        group_id = next((r.get("external_id") for r in refs if r.get("source_name")=="mitre-attack"),key)
        profiles[key] = {"canonical_actor":o["name"],"source_id":group_id,"aliases":o.get("aliases",[o["name"]]),
            "malware":[],"tools":[],"target_regions":[],"target_sectors":[],"techniques":[],"campaigns":[],
            "infrastructure":[],"profile_text":clean(o.get("description","")),"relationships":[],"field_text":{},
            "source_urls":[r["url"] for r in refs if r.get("source_name")=="mitre-attack" and r.get("url")]}
    for rel in objects.values():
        if rel["type"]!="relationship":continue
        source,target=rel.get("source_ref"),rel.get("target_ref")
        if source in profiles and target in objects:
            p=profiles[source];obj=objects[target];kind=obj["type"]
            if kind in ("malware","tool","attack-pattern"):
                field={"malware":"malware","tool":"tools","attack-pattern":"techniques"}[kind]
                names=[obj["name"]]+obj.get("x_mitre_aliases",[])
                if kind=="attack-pattern":names += [r["external_id"] for r in obj.get("external_references",[]) if r.get("source_name")=="mitre-attack" and r.get("external_id")]
                p[field].extend(names)
                p["relationships"].append({"field":field,"name":obj["name"],"description":clean(rel.get("description","")),"source_id":rel["id"]})
        if target in profiles and source in objects and objects[source]["type"]=="campaign" and rel.get("relationship_type")=="attributed-to":
            profiles[target]["campaigns"].append(objects[source]["name"])
    for p in profiles.values():
        text=p["profile_text"]+" "+" ".join(x["description"] for x in p["relationships"])
        p["target_regions"]=[x for x in REGIONS if contains(text,x)]
        p["target_sectors"]=[x for x in SECTORS if contains(text,x)]
        # Only indicators in prose, not reference URLs; coverage may be empty.
        p["infrastructure"]=sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-zA-Z0-9-]+(?:\[\.\]|\.)(?:com|net|org|info|biz)\b",text)))
        for k in ("aliases","malware","tools","techniques","campaigns"):p[k]=sorted(set(p[k]))
        p["field_text"]={
            "malware_tools":"; ".join(p["malware"]+p["tools"])+" "+" ".join(x["description"] for x in p["relationships"] if x["field"] in ("malware","tools")),
            "infrastructure":"; ".join(p["infrastructure"]),
            "targeting":"; ".join(p["target_regions"]+p["target_sectors"])+" "+p["profile_text"],
            "behavior":"; ".join(p["techniques"])+" "+" ".join(x["description"] for x in p["relationships"] if x["field"]=="techniques"),
            "aliases_campaigns":"; ".join(p["aliases"]+p["campaigns"])}
    return sorted(profiles.values(),key=lambda p:p["canonical_actor"])

class ActorRetriever:
    def prompt_evidence(self, result):
        """Prepare exactly the selected (at most three) profiles; never generate."""
        by_name={p['canonical_actor']:p for p in self.profiles}
        selected=[]
        for rank,name in enumerate(result['top3'][:3],1):
            p=by_name[name]
            selected.append({'rank':rank,**{k:p[k] for k in ('canonical_actor','source_id','source_urls','aliases','malware','tools','target_regions','target_sectors','techniques','campaigns','infrastructure','profile_text')},'evidence_scorecard':result['scorecards'][name]})
        return selected

    def __init__(self, model, profiles, cache_dir):
        import numpy as np
        self.np=np;self.model=model;self.profiles=profiles
        self.vocab={f:sorted({v for p in profiles for key in keys for v in p[key] if len(v)>=3},key=lambda x:(-len(x),x)) for f,keys in {
            "malware_tools":["malware","tools"],"aliases_campaigns":["aliases","campaigns"],"infrastructure":["infrastructure"]}.items()}
        self.df=Counter()
        for p in profiles:
            for word in set(p["aliases"]+p["campaigns"]+p["malware"]+p["tools"]+p["infrastructure"]):self.df[word.casefold()]+=1
        self.documents=[]
        for i,p in enumerate(profiles):
            for field in FIELDS:
                text=p["field_text"][field].strip()
                if not text:continue
                tokens=model.tokenizer.encode(text,add_special_tokens=False)
                for offset in range(0,len(tokens),180):
                    doc=model.tokenizer.decode(tokens[offset:offset+180],skip_special_tokens=True)
                    self.documents.append({"actor_index":i,"field":field,"text":doc})
        cache=Path(cache_dir);cache.mkdir(parents=True,exist_ok=True)
        digest=hashlib.sha256(json.dumps(self.documents,sort_keys=True).encode()).hexdigest()
        path=cache/(digest+'.npy')
        if path.exists():self.embeddings=np.load(path)
        else:
            self.embeddings=model.encode([d["text"] for d in self.documents],batch_size=64,normalize_embeddings=True,show_progress_bar=False)
            np.save(path,self.embeddings)
        self.field_rows={f:[i for i,d in enumerate(self.documents) if d["field"]==f] for f in FIELDS}

    def queries(self,report):
        # Uses only report text, not URL, gold label, or saved model attribution.
        ss=sentences(report)
        matches={f:[v for v in vocab if entity_mention(report,v,f)] for f,vocab in self.vocab.items()}
        # Drop shorter nested names to avoid treating parent-name substrings as extra facts.
        for f,values in matches.items():matches[f]=[v for v in values if not any(v.casefold()!=w.casefold() and contains(w,v) for w in values)]
        targeting=[x for x in REGIONS+SECTORS if contains(report,x)]
        behavior=[x for x in BEHAVIORS if contains(report,x)]+sorted(set(re.findall(r'\bT\d{4}(?:\.\d{3})?\b',report)))
        predicates={"malware_tools":r'malware|tool|trojan|payload|backdoor|RAT\b',"infrastructure":r'domain|IP address|server|infrastructure|command.and.control',"targeting":r'target|victim|government|sector|countr',"behavior":r'phish|inject|persist|hijack|side.load|credential|execution',"aliases_campaigns":r'campaign|attribut|known as|tracked as'}
        terms={**matches,"targeting":targeting,"behavior":behavior}
        output={}
        for field in FIELDS:
            pieces=terms.get(field,[])
            evidence=[x for x in ss if re.search(predicates[field],x,re.I)][:2]
            text='; '.join(pieces)+'. '+' '.join(evidence)
            if text.strip('. '):
                ids=self.model.tokenizer.encode(text,add_special_tokens=False)[:200]
                output[field]=self.model.tokenizer.decode(ids,skip_special_tokens=True)
        return output,terms

    def scorecard(self, p, report, terms, rrf):
        support=[];contradictions=[];scores={}
        for field,keys in [('aliases_campaigns',['aliases','campaigns']),('infrastructure',['infrastructure']),('malware_tools',['malware','tools'])]:
            hits=[v for key in keys for v in p[key] if entity_mention(report,v,field)]
            hits=list(dict.fromkeys(hits));scores[field]=sum(1/self.df[v.casefold()] for v in hits)
            hits=[v for v in hits if not any(v.casefold()!=w.casefold() and contains(w,v) for w in hits)]
            scores[field]=sum(1/self.df[v.casefold()] for v in hits)
            for hit in hits:
                snippets=[x for x in sentences(report) if contains(x,hit)]
                negative=[x for x in snippets if re.search(r'\b(?:not attributed to|ruled out|not associated with)\b',x,re.I)]
                if negative and len(negative)==len(snippets):
                    contradictions.append({'type':'explicit_report_negation','match':hit,'evidence':negative});scores[field]-=1/self.df[hit.casefold()]
                else:support.append({'field':field,'match':hit,'specificity':1/self.df[hit.casefold()],'report_evidence':snippets[:2]})
        explicit=any(contains(sentence,p['canonical_actor']) and re.search(r'\b(?:attributed to|tracked as|identified as)\b',sentence,re.I) and not re.search(r'\bnot\b',sentence,re.I) for sentence in sentences(report))
        target_hits=[x for x in p['target_regions']+p['target_sectors'] if contains(report,x)]
        behavior_hits=[x for x in terms.get('behavior',[]) if contains(p['field_text']['behavior'],x)]
        support += [{'field':'targeting','match':x} for x in target_hits]
        support += [{'field':'behavior','match':x} for x in behavior_hits]
        score=100*explicit+30*max(0,scores['aliases_campaigns'])+20*max(0,scores['infrastructure'])+10*max(0,scores['malware_tools'])+min(len(target_hits),3)*0.4+min(len(behavior_hits),3)*0.1+rrf
        return {'supporting':support,'contradicting':contradictions,'not_assessed':['No infrastructure/sector contradiction inferred from absent documentation'],'explicit_attribution':explicit,'evidence_score':score}

    def retrieve(self, report):
        qs,terms=self.queries(report)
        lists={};rrf=defaultdict(float);best=defaultdict(lambda:-1.)
        for field,q in qs.items():
            vec=self.model.encode([q],normalize_embeddings=True)[0]
            scores=self.embeddings[self.field_rows[field]]@vec
            actors={}
            for row,value in zip(self.field_rows[field],scores):
                i=self.documents[row]['actor_index'];actors[i]=max(actors.get(i,-1.),float(value))
            ranked=sorted(actors,key=lambda i:(-actors[i],self.profiles[i]['canonical_actor']))[:3]
            lists[field]=[{'actor':self.profiles[i]['canonical_actor'],'actor_index':i,'score':actors[i]} for i in ranked]
            for rank,i in enumerate(ranked,1):rrf[i]+=1/(60+rank);best[i]=max(best[i],actors[i])
        union=sorted(best,key=lambda i:(-best[i],self.profiles[i]['canonical_actor']))[:10]
        fusion=sorted(rrf,key=lambda i:(-rrf[i],self.profiles[i]['canonical_actor']))[:10]
        exact={}
        for i,p in enumerate(self.profiles):
            card=self.scorecard(p,report,terms,rrf[i])
            if any(x['field'] in ('aliases_campaigns','infrastructure','malware_tools') for x in card['supporting']):exact[i]=card
        # Multiple actors can share a tool; include all in the candidate union, then use specificity.
        # A >10 exact-match set cannot all fit; retained/dropped exact candidates are recorded.
        pool=set(fusion)|set(exact)
        cards={i:exact.get(i) or self.scorecard(self.profiles[i],report,terms,rrf[i]) for i in pool}
        reranked=sorted(pool,key=lambda i:(-cards[i]['evidence_score'],-rrf[i],self.profiles[i]['canonical_actor']))[:10]
        def names(ids):return [self.profiles[i]['canonical_actor'] for i in ids]
        return {'queries':qs,'query_terms':terms,'per_query_top3':lists,'multiquery_union':names(union),'multiquery_rrf':names(fusion),'multiquery_exact':names(reranked),'top3':names(reranked[:3]),'scorecards':{self.profiles[i]['canonical_actor']:cards[i] for i in reranked},'exact_candidates':names(sorted(exact)),'dropped_exact_candidates':names(sorted(set(exact)-set(reranked)))}

    def retrieve_graph_inclusion(self, report):
        """Candidate recall variant: exact evidence graph union plus dense pool.

        This is candidate generation only. It never reads gold labels and does
        not force the generator to select an included actor.
        """
        base = self.retrieve(report)
        selected = set(base['multiquery_exact'])
        evidence = defaultdict(list)
        # Profile fields are the local materialized actor-evidence graph. Exact
        # source names are admitted with conservative ordinary-word filtering.
        field_keys = {
            'aliases': 'aliases_campaigns', 'campaigns': 'aliases_campaigns',
            'malware': 'malware_tools', 'tools': 'malware_tools',
            'infrastructure': 'infrastructure', 'target_regions': 'targeting',
            'target_sectors': 'targeting', 'techniques': 'behavior'
        }
        for i, profile in enumerate(self.profiles):
            for key, field in field_keys.items():
                for value in profile.get(key, []):
                    # IDs, multiword names, mixed-case names, and indicators are
                    # distinctive. Single common words are excluded.
                    distinctive = (len(value) >= 5 and (' ' in value or re.search(r'[\d._-]', value) or re.search(r'[A-Z]', value[1:])))
                    if distinctive and contains(report, value):
                        evidence[i].append({'field': field, 'match': value})
            # Region/sector names are weaker graph edges, so they are included
            # only when paired with an actor profile that has such metadata.
        pool = set(selected)
        for i, matches in evidence.items():
            pool.add(self.profiles[i]['canonical_actor'])
        cards = {}
        for name in pool:
            i = next(i for i,p in enumerate(self.profiles) if p['canonical_actor']==name)
            card = self.scorecard(self.profiles[i], report, base['query_terms'], 0.0)
            card['graph_exact_evidence'] = evidence.get(i, [])
            cards[name] = card
        ranked = sorted(pool, key=lambda name: (-cards[name]['evidence_score'], -len(cards[name]['graph_exact_evidence']), name))[:10]
        return {**base, 'graph_exact_candidates': sorted(evidence and [self.profiles[i]['canonical_actor'] for i in evidence] or []), 'graph_pool': ranked, 'graph_top3': ranked[:3], 'graph_scorecards': cards}
