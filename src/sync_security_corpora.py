"""
Keep a RAG corpus updated with:
- NVD CVEs (REST API v2.0, incremental)
- MITRE ATT&CK (STIX 2.1 from GitHub)
- OWASP Top 10 (Markdown from GitHub)

Outputs a normalized folder structure you can point your indexer at.

Usage:
  python sync_security_corpora.py --root ./security_corpus --nvd-api-key $NVD_API_KEY
"""

import json, os, sys, time, shutil, subprocess, argparse, datetime as dt
from pathlib import Path
from typing import Dict, Any, Iterable, List, Optional
import requests

ISO_FMT = "%Y-%m-%dT%H:%M:%S%z"

def now_utc_iso() -> str:
    # return dt.datetime.now(dt.timezone.utc).strftime(ISO_FMT)
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

# def load_state(path: Path) -> Dict[str, Any]:
#     if path.exists():
#         return json.loads(path.read_text())
#     return {"nvd": {"last_mod_sync": "2002-01-01T00:00:00+0000"}}

def load_state(path: Path) -> Dict[str, Any]:
    if path.exists():
        state = json.loads(path.read_text())
        # Normalize old timezone format (+0000 → +00:00)
        if "nvd" in state and "last_mod_sync" in state["nvd"]:
            state["nvd"]["last_mod_sync"] = (
                state["nvd"]["last_mod_sync"]
                .replace("+0000", "+00:00")
                .replace("+00:000", "+00:00")  # safety
            )
        return state
    # default start date
    return {"nvd": {"last_mod_sync": "2002-01-01T00:00:00+00:00"}}

def save_state(path: Path, state: Dict[str, Any]) -> None:
    path.write_text(json.dumps(state, indent=2))

def ensure_dirs(root: Path) -> Dict[str, Path]:
    paths = {
        "nvd_raw": root / "nvd" / "raw",
        "nvd_norm": root / "nvd" / "normalized",
        "attack_repo": root / "mitre_attack_repo",
        "attack_norm": root / "mitre_attack" / "normalized",
        "owasp_repo": root / "owasp_top10_repo",
        "owasp_norm": root / "owasp_top10" / "normalized",
        "state": root / ".state",
    }
    for p in paths.values():
        if p.suffix != ".state":
            p.mkdir(parents=True, exist_ok=True)
    paths["state"].mkdir(parents=True, exist_ok=True)
    return paths

# -------------------------
# NVD: REST API v2.0 (incremental)
# -------------------------
# def fetch_nvd_incremental(nvd_norm_dir: Path, nvd_raw_dir: Path, state_file: Path, api_key: Optional[str]) -> int:
#     """
#     Fetch modified CVEs since last sync using NVD REST API v2.0
#     Docs: https://nvd.nist.gov/developers/vulnerabilities
#     """
#     state = load_state(state_file)
#     last_sync = state["nvd"]["last_mod_sync"]
#     start = last_sync
#     end = now_utc_iso()

#     base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
#     headers = {}
#     if api_key:
#         headers["apiKey"] = api_key

#     page = 0
#     total = 0
#     start_index = 0
#     page_size = 2000  # max as of API docs
#     params_common = {
#         "lastModStartDate": start,
#         "lastModEndDate": end,
#         "resultsPerPage": page_size,
#     }

#     while True:
#         params = dict(params_common)
#         params["startIndex"] = start_index
#         r = requests.get(base, params=params, headers=headers, timeout=90)
#         r.raise_for_status()
#         data = r.json()

#         # Save raw page
#         raw_path = nvd_raw_dir / f"nvd_{start_index}_{int(time.time())}.json"
#         raw_path.write_text(json.dumps(data))

#         cves = data.get("vulnerabilities", [])
#         total += len(cves)

#         # Normalize minimal RAG doc per CVE
#         for item in cves:
#             cve_obj = item.get("cve", {})
#             cve_id = cve_obj.get("id")
#             if not cve_id:
#                 continue
#             doc = {
#                 "source": "NVD",
#                 "cve_id": cve_id,
#                 "published": cve_obj.get("published"),
#                 "last_modified": cve_obj.get("lastModified"),
#                 "descriptions": cve_obj.get("descriptions", []),
#                 "metrics": cve_obj.get("metrics", {}),
#                 "weaknesses": cve_obj.get("weaknesses", []),
#                 "references": cve_obj.get("references", []),
#                 "configurations": cve_obj.get("configurations", []),
#             }
#             (nvd_norm_dir / f"{cve_id}.json").write_text(json.dumps(doc, ensure_ascii=False))

#         result_count = data.get("resultsPerPage", 0)
#         total_results = data.get("totalResults", 0)
#         start_index += result_count
#         if start_index >= total_results or result_count == 0:
#             break
#         page += 1

#     # Update state if successful
#     state["nvd"]["last_mod_sync"] = end
#     save_state(state_file, state)
#     return total

def fetch_nvd_incremental(nvd_norm_dir: Path, nvd_raw_dir: Path, state_file: Path, api_key: Optional[str]) -> int:
    """
    Fetch modified CVEs since last sync using NVD REST API v2.0
    Handles wide ranges by chunking into 90-day windows.
    """
    state = load_state(state_file)
    last_sync = state["nvd"]["last_mod_sync"]
    start = dt.datetime.fromisoformat(last_sync)
    end = dt.datetime.now(dt.timezone.utc)

    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": api_key} if api_key else {}
    total = 0

    # Iterate in 90-day chunks
    chunk = dt.timedelta(days=90)
    cursor = start
    while cursor < end:
        chunk_end = min(cursor + chunk, end)
        start_str = cursor.isoformat(timespec="seconds")
        end_str = chunk_end.isoformat(timespec="seconds")

        print(f"Fetching NVD {start_str} → {end_str}")
        start_index = 0
        while True:
            params = {
                "lastModStartDate": start_str,
                "lastModEndDate": end_str,
                "resultsPerPage": 2000,
                "startIndex": start_index,
            }
            r = requests.get(base, params=params, headers=headers, timeout=90)
            if r.status_code == 404:
                print(f"[WARN] 404 for window {start_str} → {end_str}, skipping.")
                break
            r.raise_for_status()
            data = r.json()

            # Save raw
            raw_path = nvd_raw_dir / f"nvd_{cursor.date()}_{start_index}.json"
            raw_path.write_text(json.dumps(data))

            cves = data.get("vulnerabilities", [])
            for item in cves:
                cve_obj = item.get("cve", {})
                cve_id = cve_obj.get("id")
                if not cve_id:
                    continue
                doc = {
                    "source": "NVD",
                    "cve_id": cve_id,
                    "published": cve_obj.get("published"),
                    "last_modified": cve_obj.get("lastModified"),
                    "descriptions": cve_obj.get("descriptions", []),
                    "metrics": cve_obj.get("metrics", {}),
                    "weaknesses": cve_obj.get("weaknesses", []),
                    "references": cve_obj.get("references", []),
                    "configurations": cve_obj.get("configurations", []),
                }
                (nvd_norm_dir / f"{cve_id}.json").write_text(json.dumps(doc, ensure_ascii=False))
            total += len(cves)

            # paging
            result_count = data.get("resultsPerPage", 0)
            total_results = data.get("totalResults", 0)
            start_index += result_count
            if start_index >= total_results or result_count == 0:
                break

        cursor = chunk_end

    # Update state
    state["nvd"]["last_mod_sync"] = end.isoformat(timespec="seconds")
    save_state(state_file, state)
    return total

# -------------------------
# MITRE ATT&CK: STIX 2.1 from GitHub repo
# -------------------------
def ensure_git_repo(repo_dir: Path, url: str, branch: str = "master") -> None:
    if (repo_dir / ".git").exists():
        subprocess.run(["git", "-C", str(repo_dir), "fetch", "--all", "--prune"], check=True)
        subprocess.run(["git", "-C", str(repo_dir), "checkout", branch], check=True)
        subprocess.run(["git", "-C", str(repo_dir), "pull"], check=True)
    else:
        subprocess.run(["git", "clone", "--depth", "1", "--branch", branch, url, str(repo_dir)], check=True)

def flatten_attack_stix(repo_dir: Path, out_dir: Path) -> int:
    """
    The mitre-attack/attack-stix-data repo contains STIX 2.1 'collections' JSON files.
    We'll emit per-object JSON docs for easy RAG ingestion.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    json_files = list(repo_dir.glob("**/*.json"))
    for jf in json_files:
        try:
            data = json.loads(jf.read_text())
        except Exception:
            continue

        # Files may be a STIX bundle or a collection index; focus on bundles with 'objects'
        objs = data.get("objects") or []
        for obj in objs:
            stix_id = obj.get("id")
            if not stix_id:
                continue
            # Build a minimal, search-friendly doc
            doc = {
                "source": "MITRE ATT&CK",
                "stix_type": obj.get("type"),
                "stix_id": stix_id,
                "name": obj.get("name"),
                "description": obj.get("description"),
                "x_mitre_domains": obj.get("x_mitre_domains") or obj.get("x_mitre_platforms"),
                "external_references": obj.get("external_references"),
                "kill_chain_phases": obj.get("kill_chain_phases"),
                "modified": obj.get("modified"),
                "created": obj.get("created"),
                "raw": obj,
            }
            # Use a filesystem-safe filename
            safe = stix_id.replace("/", "_").replace(":", "_")
            (out_dir / f"{safe}.json").write_text(json.dumps(doc, ensure_ascii=False))
            count += 1
    return count

# -------------------------
# OWASP Top 10: Markdown from GitHub
# -------------------------
def copy_owasp_markdown(repo_dir: Path, out_dir: Path) -> int:
    """
    Copy human-authored markdown into a normalized folder.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    md_files = list(repo_dir.glob("**/*.md"))
    count = 0
    for md in md_files:
        # Keep path structure shallow: e.g., owasp_top10/normalized/2021/A01-Broken_Access_Control.md
        rel = md.relative_to(repo_dir)
        target = out_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(md, target)
        count += 1
    return count

# -------------------------
# CLI
# -------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="Root output directory (RAG corpus)")
    ap.add_argument("--nvd-api-key", default=os.getenv("NVD_API_KEY"), help="NVD API key (recommended)")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    paths = ensure_dirs(root)
    state_file = paths["state"] / "state.json"

    # 1) NVD
    print("Syncing NVD (CVE 2.0 REST API) incrementally...")
    try:
        nvd_total = fetch_nvd_incremental(paths["nvd_norm"], paths["nvd_raw"], state_file, args.nvd_api_key)
        print(f"NVD: upserted {nvd_total} CVE docs.")
    except Exception as e:
        print(f"[WARN] NVD sync failed: {e}")

    # 2) MITRE ATT&CK (STIX 2.1 collections)
    print("Syncing MITRE ATT&CK STIX...")
    try:
        ensure_git_repo(paths["attack_repo"], "https://github.com/mitre-attack/attack-stix-data.git", "master")
        attack_count = flatten_attack_stix(paths["attack_repo"], paths["attack_norm"])
        print(f"ATT&CK: normalized {attack_count} STIX objects.")
    except Exception as e:
        print(f"[WARN] ATT&CK sync failed: {e}")

    # 3) OWASP Top 10 (Markdown)
    print("Syncing OWASP Top 10...")
    try:
        ensure_git_repo(paths["owasp_repo"], "https://github.com/OWASP/Top10.git", "master")
        owasp_count = copy_owasp_markdown(paths["owasp_repo"], paths["owasp_norm"])
        print(f"OWASP: copied {owasp_count} Markdown files.")
    except Exception as e:
        print(f"[WARN] OWASP sync failed: {e}")

    print("\nDone. Ready for indexing.\n")
    print(f"Index these folders:\n- {paths['nvd_norm']}\n- {paths['attack_norm']}\n- {paths['owasp_norm']}")

if __name__ == "__main__":
    main()
