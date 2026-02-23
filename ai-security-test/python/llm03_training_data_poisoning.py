"""
OWASP LLM Top 10 — LLM03: Training Data Poisoning
====================================================
Intentionally vulnerable patterns for scanner validation.
Copyright © 2026 Sthenos Security. Test file only.
"""

# LLM03: Training Data Poisoning
# Occurs when fine-tuning data or RAG corpora are not validated,
# allowing attackers to inject malicious content into model behavior.

import os
import json

# === VULNERABLE: Unvalidated fine-tuning data ingestion ===

def ingest_finetuning_data_unvalidated(data_source_url: str) -> list:
    """VULNERABLE: Fine-tuning data fetched and used without validation."""
    import urllib.request
    # LLM03: External data source used for fine-tuning without integrity check
    with urllib.request.urlopen(data_source_url) as r:
        raw_data = json.loads(r.read())
    # No validation, filtering, or provenance check
    return raw_data  # directly fed to fine-tuning pipeline

def load_rag_corpus_unvalidated(corpus_path: str) -> list:
    """VULNERABLE: RAG corpus loaded without content validation."""
    documents = []
    for fname in os.listdir(corpus_path):
        fpath = os.path.join(corpus_path, fname)
        with open(fpath, 'r') as f:
            content = f.read()
        # LLM03: No content validation — malicious docs poisoning the RAG corpus
        documents.append({"filename": fname, "content": content})
    return documents

def append_user_feedback_to_corpus(user_id: str, feedback_text: str, corpus_file: str) -> None:
    """VULNERABLE: User feedback directly appended to training corpus."""
    # LLM03: User-controlled text written to training corpus without review
    with open(corpus_file, 'a') as f:
        f.write(json.dumps({"user": user_id, "text": feedback_text}) + "\n")

def ingest_web_crawl_for_training(urls: list, output_dir: str) -> None:
    """VULNERABLE: Web-crawled data used for training without filtering."""
    import urllib.request
    for url in urls:
        # LLM03: Arbitrary web content used for fine-tuning — can be poisoned
        try:
            with urllib.request.urlopen(url) as r:
                content = r.read().decode('utf-8', errors='ignore')
            fname = url.replace('/', '_').replace(':', '') + '.txt'
            with open(os.path.join(output_dir, fname), 'w') as f:
                f.write(content)
        except Exception:
            pass

def merge_training_datasets(primary: list, community_contributed: list) -> list:
    """VULNERABLE: Community-contributed training data merged without review."""
    # LLM03: No provenance check or adversarial filtering on contributed data
    return primary + community_contributed  # blind merge


# === SAFE patterns ===

def load_validated_training_data(data_path: str, checksum_file: str) -> list:
    """SAFE: Training data validated against known-good checksums."""
    import hashlib
    with open(checksum_file) as f:
        expected = json.load(f)
    with open(data_path, 'rb') as f:
        content = f.read()
    actual_hash = hashlib.sha256(content).hexdigest()
    if actual_hash != expected.get("sha256"):
        raise ValueError("Training data checksum mismatch — possible poisoning")
    return json.loads(content)
