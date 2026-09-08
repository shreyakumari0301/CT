# TCAR — Taxonomy-Contrastive Adaptive RAG

Standalone research code for CTIBench / CTIConnect specialist RAG experiments
(MCQ / RCM / VSP / ATA / ATE). **Not** the CTA-RAG CTI-Chatbot demo repo.

## Quick start (GPU machine)

```bash
git clone https://github.com/Hammad2910/TCAR.git
cd TCAR
cp .env.example .env   # add OPENAI_API_KEY
bash run_on_gpu.sh     # setup + checks
bash run_on_gpu.sh all # RCM + VSP pilots
```

Generation uses the OpenAI API; a GPU only speeds local embeddings.

Never commit `.env`.
