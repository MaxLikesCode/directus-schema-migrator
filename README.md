# Directus Schema Migrator

A Python tool to migrate Directus schemas between instances. Pulls a schema snapshot from a source instance and applies it to a target instance with optional diffing and backup capabilities.

## Requirements

- Python 3.7+
- `requests` and `python-dotenv` packages
- PostgreSQL client tools (`pg_dump`, `pg_restore`) if using `--with-data`

## Quick Start

1. **Install dependencies:**

   ```bash
   pip install requests python-dotenv
   ```

2. **Create a `.env` file** with your Directus credentials:

   ```bash
   # Required
   DIRECTUS_SOURCE_URL=https://source.example.com
   DIRECTUS_TARGET_URL=http://localhost:8055

   # Authentication (choose one method per instance)
   # Option 1: Personal Access Tokens (recommended)
   DIRECTUS_SOURCE_TOKEN=your_source_token
   DIRECTUS_TARGET_TOKEN=your_target_token

   # Option 2: Email + Password
   # DIRECTUS_SOURCE_EMAIL=admin@example.com
   # DIRECTUS_SOURCE_PASSWORD=password
   # DIRECTUS_TARGET_EMAIL=admin@example.com
   # DIRECTUS_TARGET_PASSWORD=password

   # Optional for --with-data (PostgreSQL content migration)
   # DIRECTUS_SOURCE_DB_URL=postgres://user:pass@host:5432/source_db
   # DIRECTUS_TARGET_DB_URL=postgres://user:pass@host:5432/target_db
   ```

3. **Run the migration:**

   ```bash
   # Dry-run (preview changes only)
   python migrate.py --dry-run

   # Apply changes (backups target by default)
   python migrate.py

   # Apply without backup
   python migrate.py --no-backup

   # Apply schema and migrate content data (PostgreSQL)
   # Requires DIRECTUS_SOURCE_DB_URL and DIRECTUS_TARGET_DB_URL and pg_dump/pg_restore
   python migrate.py --with-data
   ```

## Options

- `--dry-run` - Show diff only; don't apply changes
- `--no-backup` - Skip backing up target schema (backup is enabled by default)
- `--with-data` - Migrate content data using pg_dump/pg_restore (PostgreSQL). Requires
  `DIRECTUS_SOURCE_DB_URL` and `DIRECTUS_TARGET_DB_URL`, and the `pg_dump`/`pg_restore` binaries.
- `--timeout N` - HTTP timeout in seconds (default: 30)
- `--no-verify-ssl` - Disable TLS verification (not recommended)
- `--pretty` - Pretty-print JSON outputs
- `--outdir PATH` - Output directory for snapshots/diffs (default: current dir)

## Output Files

The tool generates:

- `source_schema_snapshot.json` - Schema from source instance
- `schema_diff.json` - Differences between source and target
- `target_schema_backup.json` - Backup of target (created by default)
- `apply_result.json` - Results of the apply operation

## How It Works

1. Authenticates to both source and target Directus instances
2. Fetches schema snapshot from source
3. Computes diff against target
4. Applies changes to target (unless `--dry-run`)

## Troubleshooting

**"Payload too large" error**: If you encounter this error, increase the `MAX_PAYLOAD_SIZE` environment variable in your target Directus deployment. For example:

```bash
MAX_PAYLOAD_SIZE=100mb
```
