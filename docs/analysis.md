# Analysis

DuckDB scripts live in `scripts/duckdb` and expect Parquet output.

Example:
```
duckdb -c ".read scripts/duckdb/01_summary.sql"
```

Update the `read_parquet` path in each script if your output directory differs.
