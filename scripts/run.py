"""Run every query in sql/, write results/<name>.md and a chart."""
from __future__ import annotations

import math
from pathlib import Path

import duckdb
import numpy as np
import pandas as pd

DB = "data/vulns.duckdb"


def fmt(v, col=""):
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return ""
    if isinstance(v, (int, np.integer)):
        return f"{int(v):,}" if not any(k in col for k in ("_p", "port")) else str(int(v))
    if isinstance(v, (float, np.floating)):
        return f"{v:,.3f}".rstrip("0").rstrip(".") if abs(v) < 1000 else f"{v:,.1f}"
    if isinstance(v, pd.Timestamp):
        return v.strftime("%Y-%m-%d") if v == v.normalize() else v.strftime("%Y-%m-%d %H:%M")
    return str(v)


def md(df: pd.DataFrame) -> str:
    cols = list(df.columns)
    head = "| " + " | ".join(cols) + " |"
    sep = "|" + "|".join("---:" if pd.api.types.is_numeric_dtype(df[c]) else ":---" for c in cols) + "|"
    rows = ["| " + " | ".join(fmt(v, c) for v, c in zip(r, cols, strict=True)) + " |" for r in df.itertuples(index=False, name=None)]
    return "\n".join([head, sep, *rows])


def main() -> None:
    con = duckdb.connect(DB, read_only=True)
    Path("results").mkdir(exist_ok=True)
    out = {}
    for path in sorted(Path("sql").glob("*.sql")):
        sql = path.read_text()
        df = con.execute(sql).df()
        out[path.stem] = df
        title = next(line.lstrip("- ").strip() for line in sql.splitlines() if line.startswith("-- P"))
        Path(f"results/{path.stem}.md").write_text(f"# {title}\n\n```sql\n{sql.strip()}\n```\n\n{md(df)}\n")
        print(f"{path.stem}: {len(df)} rows")

    # ---- chart: findings by severity vs. the ones that matter ----
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    df = out["01_severity_vs_reality"]
    fig, ax = plt.subplots(figsize=(8, 4))
    x = range(len(df))
    ax.bar([i - 0.3 for i in x], df["findings"], width=0.3, label="all findings", color="#c9d6e3")
    ax.bar(x, df["epss_over_10pct"], width=0.3, label="EPSS ≥ 10%", color="#7fa6c9")
    ax.bar([i + 0.3 for i in x], df["in_cisa_kev"], width=0.3, label="in CISA KEV", color="#b22222")
    ax.set_xticks(list(x), df["severity"])
    ax.set_yscale("log")
    ax.set_ylabel("findings (log)")
    ax.set_title("3,934 findings across 10 images: severity label vs. exploitation likelihood")
    ax.legend()
    fig.tight_layout()
    Path("charts").mkdir(exist_ok=True)
    fig.savefig("charts/severity_vs_reality.png", dpi=130)
    print("chart written")


if __name__ == "__main__":
    main()
