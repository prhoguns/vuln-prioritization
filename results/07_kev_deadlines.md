# P7. KEV findings with CISA's remediation due dates (binding for US federal agencies, a sane SLA for everyone else).

```sql
-- P7. KEV findings with CISA's remediation due dates (binding for US federal agencies, a sane SLA for everyone else).
select k.cve, k.vendor, k.product, k.name, k.date_added, k.due_date, k.ransomware,
       string_agg(distinct f.image, ', ') as images, any_value(f.fixed) as fixed_version
from kev k
join findings f using (cve)
group by 1, 2, 3, 4, 5, 6, 7
order by k.due_date;
```

| cve | vendor | product | name | date_added | due_date | ransomware | images | fixed_version |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| CVE-2023-0266 | Linux | Kernel | Linux Kernel Use-After-Free Vulnerability | 2023-03-30 | 2023-04-20 | Unknown | node:14 | 4.19.282-1 |
| CVE-2023-4863 | Google | Chromium WebP | Google Chromium WebP Heap-Based Buffer Overflow Vulnerability | 2023-09-13 | 2023-10-04 | Unknown | nginx:1.18, node:14 | 0.6.1-2+deb10u3 |
| CVE-2023-44487 | IETF | HTTP/2 | HTTP/2 Rapid Reset Attack Vulnerability | 2023-10-10 | 2023-10-31 | Unknown | nginx:1.27, nginx:1.18, node:14 | 1.36.0-2+deb10u2 |
| CVE-2024-1086 | Linux | Kernel | Linux Kernel Use-After-Free Vulnerability | 2024-05-30 | 2024-06-20 | Known | node:14 | 4.19.316-1 |
| CVE-2024-36971 | Android | Kernel | Android Kernel Remote Code Execution Vulnerability | 2024-08-07 | 2024-08-28 | Unknown | node:14 | 4.19.316-1 |
| CVE-2023-0386 | Linux | Kernel | Linux Kernel Improper Ownership Management Vulnerability | 2025-06-17 | 2025-07-08 | Unknown | node:14 | 4.19.316-1 |
