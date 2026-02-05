-- P6. Where CVSS and EPSS disagree: LOW/MEDIUM findings with high exploit probability (would be missed by a
-- "criticals first" policy) and CRITICALs with negligible EPSS (would waste the week).
(select 'underrated: low/medium CVSS, EPSS >= 5%' as bucket, f.cve, f.severity, f.cvss_v3, round(e.epss, 3) as epss, f.package, f.image
 from findings f join epss e using (cve)
 where f.severity in ('LOW', 'MEDIUM') and e.epss >= 0.05
 order by e.epss desc limit 8)
union all
(select 'overrated: CRITICAL CVSS, EPSS < 0.1%', f.cve, f.severity, f.cvss_v3, round(e.epss, 4), f.package, f.image
 from findings f join epss e using (cve)
 where f.severity = 'CRITICAL' and e.epss < 0.001
 order by f.cvss_v3 desc limit 8);
