"""Load Trivy scans, CISA KEV and EPSS into data/vulns.duckdb."""
from __future__ import annotations

import gzip
import json
from pathlib import Path

import duckdb

DB = "data/vulns.duckdb"
con = duckdb.connect(DB)

# ---- findings: one row per (image, package, CVE) ----
rows = []
for path in sorted(Path("data/scans").glob("*.json")):
    scan = json.loads(path.read_text())
    image = scan["ArtifactName"]
    os_ = scan.get("Metadata", {}).get("OS", {})
    for result in scan.get("Results", []):
        for v in result.get("Vulnerabilities", []) or []:
            cvss = v.get("CVSS", {})
            nvd = cvss.get("nvd", {})
            rows.append(
                {
                    "image": image,
                    "os_family": os_.get("Family"),
                    "os_version": os_.get("Name"),
                    "os_eol": bool(os_.get("EOSL", False)),
                    "target": result.get("Target"),
                    "target_class": result.get("Class"),
                    "cve": v["VulnerabilityID"],
                    "package": v.get("PkgName"),
                    "installed": v.get("InstalledVersion"),
                    "fixed": v.get("FixedVersion") or None,
                    "severity": v.get("Severity"),
                    "cvss_v3": nvd.get("V3Score") or cvss.get("redhat", {}).get("V3Score"),
                    "published": (v.get("PublishedDate") or "")[:10] or None,
                    "title": (v.get("Title") or "")[:120],
                }
            )
con.execute("drop table if exists findings")
con.execute(
    "create table findings (image varchar, os_family varchar, os_version varchar, os_eol boolean, target varchar, target_class varchar, "
    "cve varchar, package varchar, installed varchar, fixed varchar, severity varchar, cvss_v3 double, published date, title varchar)"
)
con.executemany("insert into findings values (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", [list(r.values()) for r in rows])

# ---- CISA KEV ----
kev = json.loads(Path("data/feeds/kev.json").read_text())
con.execute("drop table if exists kev")
con.execute("create table kev (cve varchar primary key, vendor varchar, product varchar, date_added date, due_date date, ransomware varchar, name varchar)")
con.executemany(
    "insert or ignore into kev values (?,?,?,?,?,?,?)",
    [(k["cveID"], k["vendorProject"], k["product"], k["dateAdded"], k["dueDate"], k["knownRansomwareCampaignUse"], k["vulnerabilityName"]) for k in kev["vulnerabilities"]],
)

# ---- EPSS ----
with gzip.open("data/feeds/epss.csv.gz", "rt") as fh:
    header_comment = fh.readline().strip()
    Path("data/feeds/epss.csv").write_text(fh.read())
con.execute("drop table if exists epss")
con.execute("create table epss as select cve, epss::double as epss, percentile::double as percentile from read_csv('data/feeds/epss.csv', header=true)")
Path("data/feeds/epss.csv").unlink()

n = con.execute("select count(*), count(distinct cve), count(distinct image) from findings").fetchone()
print(f"findings={n[0]:,} distinct_cves={n[1]:,} images={n[2]}  kev={kev['count']:,} ({kev['catalogVersion']})  epss={con.execute('select count(*) from epss').fetchone()[0]:,} ({header_comment})")
