"""Official pySigma parsing/conversion, evaluated by SQLite, not a custom matcher."""

import importlib.metadata
from pathlib import Path
import sqlite3


class Sigma:
    def __init__(self, path):
        from sigma.collection import SigmaCollection
        from sigma.backends.sqlite import sqliteBackend

        collection = SigmaCollection.from_yaml(Path(path).read_text())
        self.rules = collection.rules
        ids = [str(rule.id) for rule in self.rules]
        if not ids or len(ids) != len(set(ids)) or "None" in ids:
            raise ValueError("Sigma rules must have unique UUID identifiers")
        self.queries = {}
        self.fields = set()
        for rule in self.rules:
            backend = sqliteBackend()
            backend.table = "events"
            self.queries[str(rule.id)] = backend.convert(SigmaCollection([rule]))
            for detection in rule.detection.detections.values():
                for item in detection.detection_items:
                    if getattr(item, "field", None):
                        self.fields.add(item.field)
        self.version = (
            "pySigma "
            + importlib.metadata.version("pysigma")
            + " / SQLite backend "
            + importlib.metadata.version("pysigma-backend-sqlite")
        )

    def evaluate(self, event, logsource):
        with sqlite3.connect(":memory:") as database:
            # Only field names parsed from reviewed rules become SQL identifiers.
            def quote(value):
                return '"' + value.replace('"', '""') + '"'

            fields = sorted(self.fields)
            database.execute(
                "CREATE TABLE events (" + ", ".join(quote(f) for f in fields) + ")"
            )
            database.execute(
                "INSERT INTO events VALUES (" + ",".join("?" for _ in fields) + ")",
                [event.get(field) for field in fields],
            )
            alerts = []
            for rule in self.rules:
                source = rule.logsource
                if any(
                    getattr(source, field)
                    and getattr(source, field) != logsource.get(field)
                    for field in ("category", "product", "service")
                ):
                    continue
                for query in self.queries[str(rule.id)]:
                    if database.execute(query).fetchone() is not None:
                        alerts.append(str(rule.id))
                        break
            return sorted(alerts)
