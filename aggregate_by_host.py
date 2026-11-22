"""Load the parser output in data/processed into the triage database.

The ingestion logic lives in database.py so the eval pipeline and this CLI
cannot drift apart.
"""
from database import ingest_processed


def main():
    counts = ingest_processed(processed_dir="data/processed")
    print("Database ingestion complete.")
    for table, rows in counts.items():
        print(f"  {table}: {rows} rows")


if __name__ == "__main__":
    main()