import os, json, faiss, numpy as np, tiktoken
from pathlib import Path
from tqdm import tqdm
from sentence_transformers import SentenceTransformer

# Embedding model
EMB = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
enc = tiktoken.get_encoding("cl100k_base")

# Folders
CORPORA = {
    "NVD": Path("data/security_corpus/nvd/normalized"),
    "ATTACK": Path("data/security_corpus/mitre_attack/normalized"),
    "OWASP": Path("data/security_corpus/owasp_top10/normalized"),
}

# ----------- Chunking -----------
def chunk(text, max_tokens=600, overlap=120):
    toks = enc.encode(text)
    out=[]
    i=0
    while i < len(toks):
        j = min(i+max_tokens, len(toks))
        out.append(enc.decode(toks[i:j]))
        i += max_tokens - overlap
    return out

# ----------- File Readers -----------
def read_json_file(fp: Path) -> str:
    """Extract useful fields from JSON (NVD / MITRE ATT&CK)."""
    try:
        data = json.loads(fp.read_text(errors="ignore"))
        fields = []
        if "cve_id" in data:  # NVD CVE
            fields.append(data["cve_id"])
        if "descriptions" in data:  # NVD multi-lang descriptions
            for d in data["descriptions"]:
                fields.append(d.get("value", ""))
        if "description" in data:  # MITRE object description
            fields.append(data["description"])
        if "name" in data:  # MITRE object name
            fields.append(data["name"])
        return "\n".join([f for f in fields if f])
    except Exception:
        return fp.read_text(errors="ignore")

def read_md_file(fp: Path) -> str:
    """Read OWASP Top 10 Markdown files."""
    return fp.read_text(errors="ignore")

# ----------- Build Index -----------
def build_index(out_dir="data/rag"):
    docs=[]
    for source, folder in CORPORA.items():
        for fp in folder.glob("**/*"):
            if fp.suffix.lower() == ".json":
                text = read_json_file(fp)
            elif fp.suffix.lower() == ".md":
                text = read_md_file(fp)
            else:
                continue

            if not text.strip():
                continue

            for c in chunk(text):
                docs.append({
                    "id": len(docs),
                    "text": c,
                    "source": str(fp),
                    "corpus": source,
                })

    print(f"Collected {len(docs)} chunks. Embedding...")

    embs = EMB.encode([d["text"] for d in docs], normalize_embeddings=True, show_progress_bar=True)
    index = faiss.IndexFlatIP(embs.shape[1])
    index.add(np.array(embs, dtype=np.float32))

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    faiss.write_index(index, str(out_dir / "faiss.index"))
    (out_dir / "segments.jsonl").write_text("\n".join(json.dumps(d) for d in docs))

    print(f"Index built: {out_dir/'faiss.index'}")
    print(f"Metadata saved: {out_dir/'segments.jsonl'}")

# ----------- CLI -----------
if __name__ == "__main__":
    build_index()
