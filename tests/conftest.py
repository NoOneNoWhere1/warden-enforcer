import os

import psycopg2
import pytest


@pytest.fixture(scope="session")
def db():
    conn = psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=int(os.getenv("POSTGRES_PORT", "5433")),
        dbname=os.getenv("POSTGRES_DB", "warden"),
        user=os.getenv("POSTGRES_USER", "postgres"),
        password=os.environ["POSTGRES_PASSWORD"],
    )
    yield conn
    conn.close()


@pytest.fixture
def db_tx(db):
    db.rollback()
    try:
        yield db
    finally:
        db.rollback()
