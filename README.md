# MedVeil

Offline, CPU-only, LLM-free privacy firewall for multilingual (English, Hindi, Hinglish)
Indian hospital records. Built for Yugaantar DevForge Track 3, "Secret Wards".

Status: under active development. The full README (setup, architecture, security design,
measured results, limitations) lands with the pipeline. The design is in
[docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md).

```bash
pip install -r requirements.txt
RAKSHA_SECRET=<secret> python main.py --input <input dir> --output <empty output dir>
```
