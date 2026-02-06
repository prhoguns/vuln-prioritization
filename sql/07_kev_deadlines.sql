-- P7. KEV findings with CISA's remediation due dates (binding for US federal agencies, a sane SLA for everyone else).
select k.cve, k.vendor, k.product, k.name, k.date_added, k.due_date, k.ransomware,
       string_agg(distinct f.image, ', ') as images, any_value(f.fixed) as fixed_version
from kev k
join findings f using (cve)
group by 1, 2, 3, 4, 5, 6, 7
order by k.due_date;
