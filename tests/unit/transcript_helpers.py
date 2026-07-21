"""Shared test utilities for unit tests."""

import json
import os


def write_jsonl(path, entries):
    """Write a list of dicts as a JSONL file, creating parent dirs as needed."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")
