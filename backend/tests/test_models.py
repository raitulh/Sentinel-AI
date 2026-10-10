from sqlalchemy import create_engine, inspect

from app.database import Base
from app import models  # noqa: F401 - registers mapped models


def test_full_schema_creates_in_memory():
    engine = create_engine("sqlite:///:memory:")
    try:
        Base.metadata.create_all(engine)
        tables = set(inspect(engine).get_table_names())
        assert {
            "users", "organizations", "memberships", "projects", "targets",
            "scan_runs", "findings", "finding_occurrences", "evidence",
            "remediation_proposals", "retest_runs", "audit_events",
        }.issubset(tables)
    finally:
        engine.dispose()
