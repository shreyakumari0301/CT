from xml.sax.saxutils import escape
W,H=1400,820
parts=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">', '<rect width="100%" height="100%" fill="white"/>', '<style>text{font-family:Arial,sans-serif;fill:#222}.title{font-size:26px;font-weight:700}.subtitle{font-size:16px;fill:#555}.head{font-size:15px;font-weight:700}.label{font-size:14px}.small{font-size:12px}.box{stroke:#555;stroke-width:1.4}.arr{stroke:#555;stroke-width:1.7;fill:none;marker-end:url(#arrow)}</style>', '<defs><marker id="arrow" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto"><path d="M0,0 L9,4.5 L0,9 z" fill="#555"/></marker></defs>']
def rect(x,y,w,h,txt,fill,stroke='#555',cls='label'):
    parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{fill}" stroke="{stroke}" class="box"/>')
    lines=txt.split('\n'); sy=y+h/2-(len(lines)-1)*8
    for i,line in enumerate(lines): parts.append(f'<text x="{x+w/2}" y="{sy+i*17}" text-anchor="middle" class="{cls}">{escape(line)}</text>')
def arrow(x1,y1,x2,y2,dash=''):
    parts.append(f'<path d="M{x1},{y1} L{x2},{y2}" class="arr"'+(f' stroke-dasharray="6,5"' if dash else '')+'/>')
parts.append('<text x="700" y="34" text-anchor="middle" class="title">CTA-RAG: task-conditional retrieval, generation, and validation</text>')
parts.append('<text x="700" y="59" text-anchor="middle" class="subtitle">The router selects one specialist before retrieval; each specialist owns its evidence source, contract, and metric.</text>')
rect(35,90,155,62,'Analyst query\ninstruction + content','#F5F5F5'); rect(230,90,205,62,'Cascade router\nregex → fallback → override','#F4A261','#9A5A00','head'); rect(480,90,125,62,'Task label\nτ̂','#F4A261','#9A5A00','head'); arrow(190,121,230,121); arrow(435,121,480,121)
heads=[('Module',35,165),('Task-matched retrieval',230,265),('Prompt + decoding',530,255),('Schema parser / output',820,245),('Metric',1120,225)]
for t,x,w in heads: rect(x,190,w,38,t,'#EDEDED','#777','head')
rows=[('Memorization\nMCQ','web CTI / ATT&CK\nk=5 cosine','direct context; letter-only\nT=0.1','A-D choice','accuracy'),('Understanding\nRCM','CTI KB (catalogue off)\nk=3','taxonomy JSON; exact\nprimary CWE','CWE identifier','exact match'),('Problem-solving\nVSP','sanitized CVE analogues\nk=3','rule-guided CVSS\nT=0.1','CVSS:3.1 vector','MAD ↓'),('Reasoning-ATE\nATE','ATT&CK domain\nsingle-hop, k=5','CoT + T-ID list\nT=0','technique set','F1'),('Reasoning-TAA\nTAA','intrusion-set store\nenriched, k=3','clue inference +\nattribution, T=0.1','actor / family','correct / plausible')]
ys=[250,350,450,550,650]
for row,y in zip(rows,ys):
  for (txt,x,w,fill) in [(row[0],35,165,'#EEF5FB'),(row[1],230,265,'#DCEAF7'),(row[2],530,255,'#E8DDF4'),(row[3],820,245,'#DFF0E3'),(row[4],1120,225,'#F5F5F5')]: rect(x,y,w,70,txt,fill,'#0072B2' if x==35 else '#555','head' if x==35 else 'label')
  arrow(200,y+35,230,y+35); arrow(495,y+35,530,y+35); arrow(785,y+35,820,y+35); arrow(1065,y+35,1120,y+35)
  arrow(542,152,117,y,dash='1')
rect(535,755,270,42,'Common answer model\n(configuration controlled)','#FFF3CD','#9A6B00','head')
parts.append('<text x="840" y="778" class="small">Only the selected row executes; other specialists are skipped.</text>')
parts.append('<text x="35" y="812" class="small">Solid arrows: data flow</text><text x="190" y="812" class="small">Dashed arrows: router fan-out</text>')
parts.append('</svg>')
open('paper_results/figures/cta_rag_architecture.svg','w',encoding='utf-8').write('\n'.join(parts))
