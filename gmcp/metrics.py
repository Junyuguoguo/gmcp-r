# gmcp/metrics.py

import csv
import os
import time
from typing import Dict, Any


class MetricsRecorder:
    def __init__(self, output_path: str):
        self.output_path = output_path
        self.rows = []

    def add_row(self, row: Dict[str, Any]):
        self.rows.append(row)

    def save(self):
        if not self.rows:
            return

        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)

        fieldnames = list(self.rows[0].keys())

        with open(self.output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.rows)


def now_ms() -> float:
    return time.time() * 1000