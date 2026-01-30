# P2. The prioritised work queue. Tier logic, in order:

```sql
-- P2. The prioritised work queue. Tier logic, in order:
--   P0  in CISA KEV (exploited in the wild) and a fix exists            -> patch this week, no discussion
--   P1  EPSS >= 0.10 (top ~5% most likely to be exploited) and fixable   -> this sprint
--   P2  CRITICAL/HIGH with EPSS >= 0.01 and fixable                       -> next sprint
--   P3  everything else fixable                                           -> routine patch cadence
--   P4  no fix available                                                  -> track, mitigate, or accept
select
    case
        when k.cve is not null and f.fixed is not null then 'P0'
        when e.epss >= 0.10 and f.fixed is not null then 'P1'
        when f.severity in ('CRITICAL', 'HIGH') and e.epss >= 0.01 and f.fixed is not null then 'P2'
        when f.fixed is not null then 'P3'
        else 'P4'
    end                                   as tier,
    f.image, f.package, f.cve, f.severity, f.cvss_v3,
    round(e.epss, 4)                      as epss,
    k.date_added                          as kev_added,
    k.ransomware                          as kev_ransomware,
    f.installed, f.fixed
from findings f
left join kev k using (cve)
left join epss e using (cve)
order by tier, e.epss desc nulls last, f.cvss_v3 desc nulls last
limit 40;
```

| tier | image | package | cve | severity | cvss_v3 | epss | kev_added | kev_ransomware | installed | fixed |
|:---|:---|:---|:---|:---|---:|---:|:---|:---|:---|:---|
| P0 | node:14 | libnghttp2-14 | CVE-2023-44487 | HIGH | 7.5 | 1 | 2023-10-10 | Unknown | 1.36.0-2+deb10u1 | 1.36.0-2+deb10u2 |
| P0 | nginx:1.18 | libnghttp2-14 | CVE-2023-44487 | HIGH | 7.5 | 1 | 2023-10-10 | Unknown | 1.36.0-2+deb10u1 | 1.36.0-2+deb10u2 |
| P0 | node:14 | libwebp6 | CVE-2023-4863 | HIGH | 8.8 | 1 | 2023-09-13 | Unknown | 0.6.1-2+deb10u1 | 0.6.1-2+deb10u3 |
| P0 | node:14 | libwebpmux3 | CVE-2023-4863 | HIGH | 8.8 | 1 | 2023-09-13 | Unknown | 0.6.1-2+deb10u1 | 0.6.1-2+deb10u3 |
| P0 | node:14 | libwebpdemux2 | CVE-2023-4863 | HIGH | 8.8 | 1 | 2023-09-13 | Unknown | 0.6.1-2+deb10u1 | 0.6.1-2+deb10u3 |
| P0 | nginx:1.18 | libwebp6 | CVE-2023-4863 | HIGH | 8.8 | 1 | 2023-09-13 | Unknown | 0.6.1-2 | 0.6.1-2+deb10u3 |
| P0 | node:14 | libwebp-dev | CVE-2023-4863 | HIGH | 8.8 | 1 | 2023-09-13 | Unknown | 0.6.1-2+deb10u1 | 0.6.1-2+deb10u3 |
| P0 | node:14 | linux-libc-dev | CVE-2024-1086 | HIGH | 7.8 | 0.281 | 2024-05-30 | Known | 4.19.269-1 | 4.19.316-1 |
| P0 | node:14 | linux-libc-dev | CVE-2023-0386 | HIGH | 7.8 | 0.079 | 2025-06-17 | Unknown | 4.19.269-1 | 4.19.316-1 |
| P0 | node:14 | linux-libc-dev | CVE-2023-0266 | HIGH | 7 | 0.037 | 2023-03-30 | Unknown | 4.19.269-1 | 4.19.282-1 |
| P0 | node:14 | linux-libc-dev | CVE-2024-36971 | HIGH | 7.8 | 0.027 | 2024-08-07 | Unknown | 4.19.269-1 | 4.19.316-1 |
| P1 | node:14 | libunbound8 | CVE-2023-50387 | HIGH | 7.5 | 1 | NaT |  | 1.9.0-2+deb10u3 | 1.9.0-2+deb10u4 |
| P1 | nginx:1.18 | openssl | CVE-2022-2068 | HIGH | 7.3 | 0.954 | NaT |  | 1.1.1d-0+deb10u6 | 1.1.1n-0+deb10u3 |
| P1 | nginx:1.18 | libssl1.1 | CVE-2022-2068 | HIGH | 7.3 | 0.954 | NaT |  | 1.1.1d-0+deb10u6 | 1.1.1n-0+deb10u3 |
| P1 | node:14 | openssh-client | CVE-2023-48795 | MEDIUM | 5.9 | 0.933 | NaT |  | 1:7.9p1-10+deb10u2 | 1:7.9p1-10+deb10u4 |
| P1 | postgres:11 | stdlib | CVE-2023-45288 | HIGH | 7.5 | 0.92 | NaT |  | v1.16.7 | 1.21.9, 1.22.2 |
| P1 | node:14 | libc6-dev | CVE-2024-2961 | HIGH | 8.8 | 0.883 | NaT |  | 2.28-10+deb10u2 | 2.28-10+deb10u3 |
| P1 | node:14 | libc6 | CVE-2024-2961 | HIGH | 8.8 | 0.883 | NaT |  | 2.28-10+deb10u2 | 2.28-10+deb10u3 |
| P1 | nginx:1.18 | libc6 | CVE-2024-2961 | HIGH | 8.8 | 0.883 | NaT |  | 2.28-10 | 2.28-10+deb10u3 |
| P1 | nginx:1.18 | libc-bin | CVE-2024-2961 | HIGH | 8.8 | 0.883 | NaT |  | 2.28-10 | 2.28-10+deb10u3 |
| P1 | node:14 | libc-dev-bin | CVE-2024-2961 | HIGH | 8.8 | 0.883 | NaT |  | 2.28-10+deb10u2 | 2.28-10+deb10u3 |
| P1 | node:14 | libc-bin | CVE-2024-2961 | HIGH | 8.8 | 0.883 | NaT |  | 2.28-10+deb10u2 | 2.28-10+deb10u3 |
| P1 | nginx:1.18 | libssl1.1 | CVE-2021-3711 | CRITICAL | 9.8 | 0.878 | NaT |  | 1.1.1d-0+deb10u6 | 1.1.1d-0+deb10u7 |
| P1 | nginx:1.18 | openssl | CVE-2021-3711 | CRITICAL | 9.8 | 0.878 | NaT |  | 1.1.1d-0+deb10u6 | 1.1.1d-0+deb10u7 |
| P1 | nginx:1.18 | libnghttp2-14 | CVE-2024-28182 | MEDIUM | 5.3 | 0.85 | NaT |  | 1.36.0-2+deb10u1 | 1.36.0-2+deb10u3 |
| P1 | node:14 | libnghttp2-14 | CVE-2024-28182 | MEDIUM | 5.3 | 0.85 | NaT |  | 1.36.0-2+deb10u1 | 1.36.0-2+deb10u3 |
| P1 | nginx:1.18 | libssl1.1 | CVE-2022-1292 | HIGH | 7.3 | 0.826 | NaT |  | 1.1.1d-0+deb10u6 | 1.1.1n-0+deb10u2 |
| P1 | nginx:1.18 | openssl | CVE-2022-1292 | HIGH | 7.3 | 0.826 | NaT |  | 1.1.1d-0+deb10u6 | 1.1.1n-0+deb10u2 |
| P1 | node:14 | libunbound8 | CVE-2023-50868 | HIGH | 7.5 | 0.817 | NaT |  | 1.9.0-2+deb10u3 | 1.9.0-2+deb10u4 |
| P1 | node:14 | openssh-client | CVE-2023-38408 | CRITICAL | 9.8 | 0.797 | NaT |  | 1:7.9p1-10+deb10u2 | 1:7.9p1-10+deb10u3 |
| P1 | node:14 | libssl-dev | CVE-2023-2650 | MEDIUM | 6.5 | 0.751 | NaT |  | 1.1.1n-0+deb10u4 | 1.1.1n-0+deb10u5 |
| P1 | node:14 | openssl | CVE-2023-2650 | MEDIUM | 6.5 | 0.751 | NaT |  | 1.1.1n-0+deb10u4 | 1.1.1n-0+deb10u5 |
| P1 | node:14 | libssl1.1 | CVE-2023-2650 | MEDIUM | 6.5 | 0.751 | NaT |  | 1.1.1n-0+deb10u4 | 1.1.1n-0+deb10u5 |
| P1 | nginx:1.18 | libssl1.1 | CVE-2023-2650 | MEDIUM | 6.5 | 0.751 | NaT |  | 1.1.1d-0+deb10u6 | 1.1.1n-0+deb10u5 |
| P1 | nginx:1.18 | openssl | CVE-2023-2650 | MEDIUM | 6.5 | 0.751 | NaT |  | 1.1.1d-0+deb10u6 | 1.1.1n-0+deb10u5 |
| P1 | nginx:1.18 | openssl | CVE-2022-0778 | HIGH | 7.5 | 0.732 | NaT |  | 1.1.1d-0+deb10u6 | 1.1.1d-0+deb10u8 |
| P1 | nginx:1.18 | libssl1.1 | CVE-2022-0778 | HIGH | 7.5 | 0.732 | NaT |  | 1.1.1d-0+deb10u6 | 1.1.1d-0+deb10u8 |
| P1 | python:3.8-slim | libsqlite3-0 | CVE-2025-6965 | HIGH | 7.7 | 0.726 | NaT |  | 3.40.1-2 | 3.40.1-2+deb12u2 |
| P1 | nginx:1.18 | libldap-2.4-2 | CVE-2022-29155 | CRITICAL | 9.8 | 0.645 | NaT |  | 2.4.47+dfsg-3+deb10u6 | 2.4.47+dfsg-3+deb10u7 |
| P1 | nginx:1.18 | libldap-common | CVE-2022-29155 | CRITICAL | 9.8 | 0.645 | NaT |  | 2.4.47+dfsg-3+deb10u6 | 2.4.47+dfsg-3+deb10u7 |
