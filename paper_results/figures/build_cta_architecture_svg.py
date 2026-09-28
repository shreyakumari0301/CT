from xml.sax.saxutils import escape
W,H=1480,900
parts=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">', '<rect width="100%" height="100%" fill="white"/>', '<style>text{font-family:Arial,sans-serif;fill:#222}.title{font-size:24px;font-weight:700}.subtitle{font-size:15px;fill:#555}.head{font-size:14px;font-weight:700}.label{font-size:13px}.small{font-size:12px}.box{stroke:#555;stroke-width:1.4}.arr{stroke:#555;stroke-width:1.7;fill:none;marker-end:url(#arrow)}</style>', '<defs><marker id="arrow" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto"><path d="M0,0 L9,4.5 L0,9 z" fill="#555"/></marker></defs>']
def rect(x,y,w,h,txt,fill,stroke='#555',cls='label'):
    parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{fill}" stroke="{stroke}" class="box"/>')
    lines=txt.split('\n'); sy=y+h/2-(len(lines)-1)*8
    for i,line in enumerate(lines): parts.append(f'<text x="{x+w/2}" y="{sy+i*16}" text-anchor="middle" class="{cls}">{escape(line)}</text>')
def arrow(x1,y1,x2,y2,dash=''):
    parts.append(f'<path d="M{x1},{y1} L{x2},{y2}" class="arr"'+(f' stroke-dasharray="6,5"' if dash else '')+'/>')
parts.append('<text x="740" y="32" text-anchor="middle" class="title">CTA-RAG: four cognitive modes, then schema specialists</text>')
parts.append('<text x="740" y="54" text-anchor="middle" class="subtitle">The router picks one mode before retrieval. Reasoning is a single mode that splits into ATE, ATA, and TAA.</text>')
rect(40,78,200,56,'Analyst query\ninstruction + content','#EEF5FB')
rect(300,78,240,56,'Cascade router\nregex → classifier → override','#F4A261','#9A5A00','head')
rect(600,78,160,56,'Cognitive mode','#F4A261','#9A5A00','head')
arrow(240,106,300,106); arrow(540,106,600,106)
# modes
rect(40,160,210,48,'Memorization','#C8E6C9','#2E7D32','head')
rect(270,160,210,48,'Understanding','#B2EBF2','#00838F','head')
rect(500,160,210,48,'Problem-solving','#D1C4E9','#6A1B9A','head')
rect(730,160,710,48,'Reasoning (one mode)','#E1BEE7','#6A1B9A','head')
arrow(680,106,145,160,dash='1'); arrow(680,106,375,160,dash='1'); arrow(680,106,605,160,dash='1'); arrow(680,106,1085,160,dash='1')
# specialists
ys=230
rects=[
 (40,ys,210,52,'CTI-MCQ','#E8F5E9'),
 (270,ys,210,52,'CTI-RCM','#E0F7FA'),
 (500,ys,210,52,'CTI-VSP','#EDE7F6'),
 (730,ys,220,52,'CTI-ATE\ntechnique extraction','#F3E5F5'),
 (970,ys,220,52,'CTI-ATA\ntechnique ID (RRF k=60)','#FFF3E0'),
 (1210,ys,230,52,'CTI-TAA\nactor (CombSUM top-3)','#FCE4EC'),
]
for x,y,w,h,txt,fill in rects:
    rect(x,y,w,h,txt,fill,'#555','head' if '\n' not in txt else 'label')
arrow(145,208,145,230); arrow(375,208,375,230); arrow(605,208,605,230)
arrow(1085,208,840,230); arrow(1085,208,1080,230); arrow(1085,208,1325,230)
# stages
def col(x,w,rows,y0=300):
    y=y0
    prev=None
    for txt,fill in rows:
        rect(x,y,w,58,txt,fill)
        if prev is not None:
            arrow(x+w/2, prev+58, x+w/2, y)
        prev=y
        y += 70
    return y
col(40,210,[('Web CTI / ATT&CK  k=5','#fff'),('Letter-only prompt','#E8F5E9'),('A–D accuracy','#FFF9C4')])
col(270,210,[('CTI KB  k=3','#fff'),('Taxonomy JSON','#E0F7FA'),('CWE exact match','#FFF9C4')])
col(500,210,[('Sanitized CVE k=3','#fff'),('Rule-guided CVSS','#EDE7F6'),('Vector MAD','#FFF9C4')])
col(730,220,[('ATT&CK domain k=5','#fff'),('CoT + T-ID list','#F3E5F5'),('Technique-set F1','#FFF9C4')])
col(970,220,[('Procedure + def. + memo','#fff'),('RRF 1/(60+rank)','#FFF3E0'),('Constrained top-5 ID','#FFF9C4')])
col(1210,230,[('3 gold-blind actor lists','#fff'),('CombSUM min-max ranks','#FCE4EC'),('Constrained top-3 pick','#FFF9C4')])
parts.append('<text x="40" y="880" class="small">Solid arrows: data flow. Dashed arrows: router fan-out to a cognitive mode. Only the selected specialist executes.</text>')
parts.append('</svg>')
open('paper_results/figures/cta_rag_architecture.svg','w',encoding='utf-8').write('\n'.join(parts))
print('svg written')
