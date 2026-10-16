import json
import os
from pathlib import Path


BASE_DIR = Path.home() / "Desktop" / "ML Projects" / "nexi"

class SystemManager:
    # Class prop so it can be changed later (e.g. per-project or via config)
    FILE_NAMES = ["sbom.json", "saasbom.json", "obom.json"]

    def __init__(self, inventory_dir = BASE_DIR):
        self.components = []
        self.inventory_dir = inventory_dir
        self.load_files()

    def load_files(self):
        # Load your separate JSON files safely
        for name in self.FILE_NAMES:
            path = os.path.join(self.inventory_dir, name)
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                    # CycloneDX components can be in "components" or "services"
                    comps = data.get("components", []) + data.get("services", [])
                    for c in comps:
                        self.components.append({
                            "name": c.get("name", "").lower(),
                            "vendor": c.get("vendor", "").lower(),
                            "type": c.get("type", "unknown"),
                            "purl": c.get("purl", "")
                        })
                print(f"Loaded {path} successfully.")
            except FileNotFoundError:
                print(f"Notice: {path} not found, skipping.")

    def search(self, query: str) -> list:
        """Fast keyword search across all loaded inventories."""
        query = query.lower()
        matches = [
            item for item in self.components
            if query in item["name"] or query in item["vendor"] or query in item["purl"]
        ]
        return matches


inventory = SystemManager()
