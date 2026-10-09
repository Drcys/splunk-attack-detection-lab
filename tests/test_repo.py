"""Static checks that keep the detection content valid and consistent."""
import configparser
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ATTACK_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def test_dashboard_is_valid_simple_xml():
    root = ET.parse(ROOT / "dashboards" / "investigation_dashboard.xml").getroot()
    assert root.tag == "form"
    queries = [q.text for q in root.iter("query")]
    assert len(queries) >= 5 and all(q and "index=main" in q for q in queries)


def test_savedsearches_parse_and_are_scheduled():
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    cp.optionxform = str
    text = (ROOT / "detections" / "savedsearches.conf").read_text(encoding="utf-8")
    cp.read_string(text.replace("\\\n", " "))
    assert len(cp.sections()) == 4
    for name in cp.sections():
        s = cp[name]
        assert s.get("enableSched") == "1", name
        assert s.get("cron_schedule"), name
        assert "index=main" in s.get("search", ""), name
        assert re.search(r"T\d{4}", name), f"{name}: no ATT&CK ID in title"


def test_sigma_rules_have_required_fields():
    rules = list((ROOT / "sigma").glob("*.yml"))
    assert len(rules) == 3
    ids = set()
    for path in rules:
        rule = next(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        for key in ("title", "id", "logsource", "detection", "level", "tags"):
            assert key in rule, f"{path.name}: missing {key}"
        assert "condition" in rule["detection"], path.name
        assert any(t.startswith("attack.t") for t in rule["tags"]), path.name
        assert rule["id"] not in ids, f"duplicate id in {path.name}"
        ids.add(rule["id"])


def test_navigator_layer_uses_valid_technique_ids():
    layer = json.loads((ROOT / "attack-navigator" / "layer.json").read_text(encoding="utf-8"))
    ids = [t["techniqueID"] for t in layer["techniques"]]
    assert ids and all(ATTACK_ID.match(i) for i in ids)


def test_readme_links_resolve():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for target in re.findall(r"\]\(((?!https?://|#)[^)]+)\)", readme):
        assert (ROOT / target).exists(), f"broken link: {target}"
