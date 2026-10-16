from typing import Optional


def format_kev_entry(cve_id: str, entry: dict, epss: Optional[dict] = None) -> str:
    cwes = entry.get("cwes") or []
    epss_text = f"{epss['epss']:.3f} (percentile {epss['percentile']:.3f})" if epss else "unscored"
    return (
        f"- {cve_id}: vendor={entry.get('vendorProject', 'unknown')}, product={entry.get('product', 'unknown')}, "
        f"name={entry.get('vulnerabilityName', '')}, cwes={', '.join(cwes) or 'Unknown'}, "
        f"known_ransomware_use={entry.get('knownRansomwareCampaignUse', 'Unknown')}, epss={epss_text}, "
        f"description={entry.get('shortDescription', 'Unknown')}"
    )