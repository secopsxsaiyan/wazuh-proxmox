#!/usr/bin/env python3
"""Generate the 'Proxmox VE Security & Threats' dashboard NDJSON (stdlib only).

The OVERVIEW + AUTH panels span ALL PVE security activity — both Wazuh's STOCK Proxmox VE
ruleset (group `proxmox-ve`: pvedaemon auth 87201/87202/87203) AND this pack's custom rules
(100390-100423). The stock auth rules are the bulk of the signal on a healthy box; scoping the
board to the custom group alone (`rule.groups: proxmox`) leaves it blank until a rare custom-pack
event fires — including the "hosts (by agent)" panel, since that host only appears once it emits a
matching alert. So overview/auth panels use `rule.groups: (proxmox or "proxmox-ve")` and the auth
panels add the stock pvedaemon rule IDs.

The HIGH-VALUE DETECTION panels (VM/CT destruction 100391, attack roll-up, lifecycle, pveum/admin,
/etc/pve FIM) stay scoped to the specific CUSTOM rule IDs — these legitimately read low/zero on a
healthy box and are the pack's value-add; mixing stock auth into them would dilute the signal.

Some custom detections are forward-looking (no positive sample on a quiet box) and populate when the
event first occurs; rule paths are validated with wazuh-logtest. The web source-IP panel needs an
auth FAILURE (stock 87201/87202 carry srcip) or a successful pveproxy login (custom 100416) — a box
with neither legitimately shows no source IP yet."""
import json
ALERTS = "wazuh-alerts-*"
OSD = "2.16.0"
objects = []

def ss(query=""):
    return json.dumps({"query": {"query": query, "language": "kuery"}, "filter": [],
                       "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})

def viz(vid, title, vistype, aggs, params, query=""):
    # Tables need bucket aggs with schema "bucket" to split rows; "segment"/"group"
    # (right for pie/xy) make a table show only the metric count. Force "bucket".
    if vistype == "table":
        for _a in aggs:
            if _a.get("type") in ("terms", "date_histogram", "histogram") \
                    and _a.get("schema") in ("segment", "group"):
                _a["schema"] = "bucket"
    objects.append({"id": vid, "type": "visualization", "attributes": {
        "title": title, "visState": json.dumps({"title": title, "type": vistype, "aggs": aggs, "params": params}),
        "uiStateJSON": "{}", "description": "", "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": ss(query)}},
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": ALERTS}]})
    return vid

def dash(did, title, panels, desc=""):
    pj, refs = [], []
    for i, v in enumerate(panels):
        pi = str(i)
        pj.append({"version": OSD, "gridData": {"x": (i % 2) * 24, "y": (i // 2) * 15, "w": 24, "h": 15, "i": pi},
                   "panelIndex": pi, "embeddableConfig": {}, "panelRefName": "panel_" + pi})
        refs.append({"name": "panel_" + pi, "type": "visualization", "id": v})
    objects.append({"id": did, "type": "dashboard", "attributes": {
        "title": title, "hits": 0, "description": desc, "panelsJSON": json.dumps(pj),
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}), "version": 1, "timeRestore": False,
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []})}},
        "references": refs})

def count(i="1"): return {"id": i, "enabled": True, "type": "count", "schema": "metric", "params": {}}
def terms(i, f, n=10, schema="segment"): return {"id": i, "enabled": True, "type": "terms", "schema": schema,
    "params": {"field": f, "orderBy": "1", "order": "desc", "size": n, "otherBucket": False,
               "otherBucketLabel": "Other", "missingBucket": False, "missingBucketLabel": "Missing"}}
def datehist(i): return {"id": i, "enabled": True, "type": "date_histogram", "schema": "segment",
    "params": {"field": "@timestamp", "useNormalizedEsInterval": True, "interval": "auto",
               "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}}
def p_table(): return {"perPage": 12, "showPartialRows": False, "showMetricsAtAllLevels": False,
    "sort": {"columnIndex": None, "direction": None}, "showTotal": True, "totalFunc": "sum", "percentageCol": ""}
def p_pie(): return {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
    "isDonut": True, "labels": {"show": False, "values": True, "last_level": True, "truncate": 100}}
def p_metric(sub): return {"addTooltip": True, "addLegend": False, "type": "metric", "metric": {
    "percentageMode": False, "useRanges": False, "colorSchema": "Green to Red", "metricColorMode": "None",
    "colorsRange": [{"from": 0, "to": 1000000}], "labels": {"show": True}, "invertColors": False,
    "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": sub, "fontSize": 40}}}
def p_area():
    return {"type": "histogram", "grid": {"categoryLines": False},
        "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True, "style": {},
            "scale": {"type": "linear"}, "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
        "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True,
            "style": {}, "scale": {"type": "linear", "mode": "normal"},
            "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100}, "title": {"text": "events"}}],
        "seriesParams": [{"show": True, "type": "area", "mode": "stacked", "data": {"label": "Count", "id": "1"},
            "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True,
            "interpolate": "linear"}], "addTooltip": True, "addLegend": True, "legendPosition": "right",
        "times": [], "addTimeMarker": False, "labels": {}, "thresholdLine": {"show": False, "value": 10, "width": 1,
            "style": "full", "color": "#E7664C"}}

# ---- query scopes ----
# Overview panels span ALL PVE activity (stock proxmox-ve group + this pack's custom rules, which
# also carry the proxmox-ve group via the rules-file wrapper). proxmox-ve is quoted because of the
# hyphen. Detection panels below stay on specific CUSTOM rule IDs (the pack's value-add).
PVEALL    = 'rule.groups: (proxmox or "proxmox-ve")'       # stock pvedaemon auth + custom pack
SEC       = PVEALL + " AND rule.level >= 3"                 # master overview (timeline/types/mitre/agents)
HIGH      = PVEALL + " AND rule.level >= 7"                 # notable + triage
DESTRUCT  = "rule.id:100391"                                # VM/CT destroyed (custom, near-zero FP)
ATTACK    = "rule.id:(100391 or 100418 or 100419 or 100420 or 100421)"  # destroy/web-brute/user.cfg/priv/corosync
LIFECYCLE = "rule.id:(100390 or 100391 or 100392 or 100393)"
ADMIN     = "rule.id:(100394 or 100419)"                    # pveum + user.cfg change
# Auth panels = custom pveproxy web-auth (100416-402, srcip on SUCCESS) + stock pvedaemon auth
# (87201 fail / 87202 brute / 87203 success). Populates from stock auth even before any pveproxy
# line is collected, giving a complete PVE auth picture.
AUTHALL   = "rule.id:(100416 or 100417 or 100418 or 87201 or 87202 or 87203)"  # all PVE auth
AUTHFAIL  = "rule.id:(100417 or 100418 or 87201 or 87202)"  # failures + brute force
WEBSRC    = "rule.id:(100416 or 100417 or 100418 or 87201 or 87202)"  # those that carry canonical srcip
FIM       = "rule.id:(100419 or 100420 or 100421 or 100422 or 100423)"

# Row 1 — headline KPIs
viz("pve-kpi-destroy", "VM/CT destructions (qmdestroy / vzdestroy)", "metric",
    [count("1")], p_metric("T1578.001/T1485 — near-zero FP"), query=DESTRUCT)
viz("pve-kpi-attacks", "High-confidence attack events", "metric",
    [count("1")], p_metric("destruction / web brute force / rogue-admin / key / cluster"), query=ATTACK)
# Row 2 — trend + event mix
viz("pve-timeline", "Proxmox security events over time (by level)", "area",
    [count("1"), datehist("2"), terms("3", "rule.level", 6, schema="group")], p_area(), query=SEC)
viz("pve-eventtypes", "Proxmox event types", "pie",
    [count("1"), terms("2", "rule.description", 10)], p_pie(), query=SEC)
# Row 3 — who (web-UI/API source IPs + auth activity)
viz("pve-websrc", "PVE web-UI/API source IPs (canonical srcip — feeds MISP IOC + GeoIP)", "table",
    [count("1"), terms("2", "data.srcip", 20), terms("3", "GeoLocation.country_name", 1)], p_table(), query=WEBSRC)
viz("pve-auth", "PVE web-UI/API authentication (success / failure)", "table",
    [count("1"), terms("2", "rule.description", 12)], p_table(), query=AUTHALL)
# Row 4 — auth failures/brute force + VM lifecycle
viz("pve-brute", "Auth failures & brute-force sources", "table",
    [count("1"), terms("2", "data.srcip", 15), terms("3", "rule.description", 2)], p_table(), query=AUTHFAIL)
viz("pve-lifecycle", "VM/CT lifecycle (create / destroy / backup / migrate)", "table",
    [count("1"), terms("2", "rule.description", 10), terms("3", "agent.name", 4)], p_table(), query=LIFECYCLE)
# Row 5 — admin/account + /etc/pve FIM
viz("pve-admin", "Admin & account operations (pveum / user.cfg)", "table",
    [count("1"), terms("2", "rule.description", 8), terms("3", "agent.name", 4)], p_table(), query=ADMIN)
viz("pve-fim", "/etc/pve configuration changes (FIM)", "table",
    [count("1"), terms("2", "syscheck.path", 20)], p_table(), query=FIM)
# Row 6 — MITRE + high severity
viz("pve-mitre", "MITRE ATT&CK techniques observed", "pie",
    [count("1"), terms("2", "rule.mitre.id", 15)], p_pie(), query=SEC)
viz("pve-high", "High-severity Proxmox alerts (L>=7)", "table",
    [count("1"), terms("2", "rule.description", 15), terms("3", "rule.level", 1)], p_table(), query=HIGH)
# Row 7 — per host + high-confidence attack detail
viz("pve-agents", "Proxmox hosts (by agent)", "table",
    [count("1"), terms("2", "agent.name", 15)], p_table(), query=SEC)
viz("pve-attack-detail", "High-confidence attack events — detail", "table",
    [count("1"), terms("2", "rule.description", 12), terms("3", "rule.level", 1)], p_table(), query=ATTACK)

dash("proxmox-security-threats", "Proxmox VE Security & Threats",
     ["pve-kpi-destroy", "pve-kpi-attacks", "pve-timeline", "pve-eventtypes",
      "pve-websrc", "pve-auth", "pve-brute", "pve-lifecycle",
      "pve-admin", "pve-fim", "pve-mitre", "pve-high",
      "pve-agents", "pve-attack-detail"],
     "Proxmox VE hypervisor security. Overview & auth panels span ALL PVE activity (stock proxmox-ve "
     "auth rules 87201/87202/87203 + this pack's custom rules 100390-100423); detection panels are "
     "scoped to the custom rules: VM/CT lifecycle and DESTRUCTION (anti-recovery), pveum admin / "
     "API-token and /etc/pve/user.cfg rogue-admin changes, PVE web-UI/API brute force (canonical srcip "
     "-> MISP IOC + GeoIP), and /etc/pve cluster-config FIM (priv keys, corosync, firewall, storage). "
     "Several detection panels are forward-looking and populate when the event first occurs.")

with open("wazuh_proxmox_dashboard.ndjson", "w") as f:
    for o in objects:
        f.write(json.dumps(o) + "\n")
print("wrote", len(objects), "objects (1 dashboard,", len(objects) - 1, "visualizations)")
