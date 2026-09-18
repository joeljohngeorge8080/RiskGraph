#!/bin/sh
# Creates the test database alongside the dev one so host-run `pytest -m db` works
# against the dev compose stack without a second Postgres.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
  SELECT 'CREATE DATABASE riskgraph_test OWNER "$POSTGRES_USER"'
  WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'riskgraph_test')\gexec
SQL
