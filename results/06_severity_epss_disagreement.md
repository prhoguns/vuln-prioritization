# P6. Where CVSS and EPSS disagree: LOW/MEDIUM findings with high exploit probability (would be missed by a

```sql
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
```

| bucket | cve | severity | cvss_v3 | epss | package | image |
|:---|:---|:---|---:|---:|:---|:---|
| underrated: low/medium CVSS, EPSS >= 5% | CVE-2023-44487 | LOW | 7.5 | 1 | nginx | nginx:1.27 |
| underrated: low/medium CVSS, EPSS >= 5% | CVE-2023-48795 | MEDIUM | 5.9 | 0.933 | openssh-client | node:14 |
| underrated: low/medium CVSS, EPSS >= 5% | CVE-2024-28182 | MEDIUM | 5.3 | 0.85 | libnghttp2-14 | node:14 |
| underrated: low/medium CVSS, EPSS >= 5% | CVE-2024-28182 | MEDIUM | 5.3 | 0.85 | libnghttp2-14 | nginx:1.18 |
| underrated: low/medium CVSS, EPSS >= 5% | CVE-2023-2650 | MEDIUM | 6.5 | 0.751 | libssl-dev | node:14 |
| underrated: low/medium CVSS, EPSS >= 5% | CVE-2023-2650 | MEDIUM | 6.5 | 0.751 | libssl1.1 | node:14 |
| underrated: low/medium CVSS, EPSS >= 5% | CVE-2023-2650 | MEDIUM | 6.5 | 0.751 | openssl | nginx:1.18 |
| underrated: low/medium CVSS, EPSS >= 5% | CVE-2023-2650 | MEDIUM | 6.5 | 0.751 | libssl1.1 | nginx:1.18 |
