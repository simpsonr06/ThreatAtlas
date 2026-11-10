
import pytest

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

import app.models

from app.db import Base
from app.models import IOC, IOCSource
from app.schemas.ioc import IOCCreate, IOCSourceCreate
from app.services.ioc_service import (
    IOCNotFoundError,
    create_ioc,
    get_ioc,
    list_iocs,
    delete_ioc,
)


@pytest.fixture
def session():
    """Create an isolated in-memory database for each test."""

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(bind=engine)

    with Session(engine) as db:
        yield db

    engine.dispose()


def make_payload(
    value="192.0.2.10",
    ioc_type=None,
    source_name="manual",
    source_record_id=None,
    confidence=50.0,
):
    """Build a reusable IOC creation payload."""

    return IOCCreate(
        value=value,
        ioc_type=ioc_type,
        source=IOCSourceCreate(
            source_name=source_name,
            source_record_id=source_record_id,
            confidence=confidence,
        ),
    )


# ---------------------------------------------------------
# CREATE IOC TESTS
# ---------------------------------------------------------


def test_create_ioc_successfully(session):
    ioc = create_ioc(
        session,
        make_payload(),
    )

    assert ioc.id is not None
    assert ioc.value == "192.0.2.10"
    assert ioc.normalized_value == "192.0.2.10"
    assert ioc.ioc_type == "ip"
    assert len(ioc.sources) == 1


def test_create_domain_ioc_normalizes_value(session):
    ioc = create_ioc(
        session,
        make_payload(
            value=" MALICIOUS.Example.COM. ",
        ),
    )

    assert ioc.ioc_type == "domain"
    assert ioc.normalized_value == "malicious.example.com"


def test_create_url_ioc(session):
    ioc = create_ioc(
        session,
        make_payload(
            value="HTTPS://Example.com:443/login",
        ),
    )

    assert ioc.ioc_type == "url"
    assert ioc.normalized_value == "https://example.com/login"


def test_create_hash_ioc(session):
    digest = "D" * 64

    ioc = create_ioc(
        session,
        make_payload(value=digest),
    )

    assert ioc.ioc_type == "file_hash"
    assert ioc.normalized_value == digest.lower()


# ---------------------------------------------------------
# SOURCE ATTRIBUTION AND DEDUPLICATION
# ---------------------------------------------------------


def test_create_ioc_with_source_attribution(session):
    ioc = create_ioc(
        session,
        make_payload(
            source_name="URLhaus",
            source_record_id="record-001",
            confidence=90.0,
        ),
    )

    assert len(ioc.sources) == 1

    source = ioc.sources[0]

    assert source.source_name == "URLhaus"
    assert source.source_record_id == "record-001"
    assert source.confidence == 90.0


def test_same_ioc_from_multiple_sources_is_merged(session):
    first = create_ioc(
        session,
        make_payload(
            value="malicious.example.com",
            source_name="URLhaus",
            source_record_id="url-001",
        ),
    )

    second = create_ioc(
        session,
        make_payload(
            value="MALICIOUS.EXAMPLE.COM",
            source_name="ThreatFox",
            source_record_id="threat-001",
        ),
    )

    assert first.id == second.id
    assert len(second.sources) == 2

    source_names = {
        source.source_name
        for source in second.sources
    }

    assert source_names == {"URLhaus", "ThreatFox"}


def test_duplicate_source_record_is_idempotent(session):
    payload = make_payload(
        value="192.0.2.15",
        source_name="URLhaus",
        source_record_id="record-duplicate",
    )

    first = create_ioc(session, payload)
    second = create_ioc(session, payload)

    assert first.id == second.id
    assert len(second.sources) == 1


def test_different_source_records_are_preserved(session):
    first = create_ioc(
        session,
        make_payload(
            value="192.0.2.20",
            source_name="URLhaus",
            source_record_id="record-001",
        ),
    )

    second = create_ioc(
        session,
        make_payload(
            value="192.0.2.20",
            source_name="URLhaus",
            source_record_id="record-002",
        ),
    )

    assert first.id == second.id
    assert len(second.sources) == 2

    record_ids = {
        source.source_record_id
        for source in second.sources
    }

    assert record_ids == {"record-001", "record-002"}


def test_duplicate_manual_source_is_not_duplicated(session):
    payload = make_payload(
        value="192.0.2.25",
        source_name="manual",
    )

    create_ioc(session, payload)
    result = create_ioc(session, payload)

    assert len(result.sources) == 1


# ---------------------------------------------------------
# RETRIEVAL TESTS
# ---------------------------------------------------------


def test_get_ioc_successfully(session):
    created = create_ioc(
        session,
        make_payload(),
    )

    result = get_ioc(session, created.id)

    assert result.id == created.id
    assert result.normalized_value == "192.0.2.10"


def test_get_ioc_includes_sources(session):
    created = create_ioc(
        session,
        make_payload(
            source_name="ThreatFox",
            source_record_id="tf-001",
        ),
    )

    result = get_ioc(session, created.id)

    assert len(result.sources) == 1
    assert result.sources[0].source_name == "ThreatFox"


def test_get_missing_ioc_raises_error(session):
    with pytest.raises(IOCNotFoundError):
        get_ioc(session, 99999)


# ---------------------------------------------------------
# LISTING, FILTERING AND PAGINATION
# ---------------------------------------------------------


def test_list_iocs_returns_all_records(session):
    create_ioc(session, make_payload("192.0.2.10"))
    create_ioc(session, make_payload("192.0.2.11"))
    create_ioc(session, make_payload("192.0.2.12"))

    result = list_iocs(session)

    assert result["total"] == 3
    assert len(result["items"]) == 3
    assert result["page"] == 1
    assert result["page_size"] == 20
    assert result["total_pages"] == 1


def test_list_iocs_filters_by_type(session):
    create_ioc(session, make_payload("192.0.2.10"))
    create_ioc(session, make_payload("192.0.2.11"))
    create_ioc(session, make_payload("malicious.example.com"))

    result = list_iocs(
        session,
        ioc_type="ip",
    )

    assert result["total"] == 2
    assert all(
        item.ioc_type == "ip"
        for item in result["items"]
    )


def test_list_iocs_searches_normalized_value(session):
    create_ioc(session, make_payload("192.0.2.10"))
    create_ioc(session, make_payload("192.0.2.11"))
    create_ioc(session, make_payload("malicious.example.com"))

    result = list_iocs(
        session,
        search="malicious",
    )

    assert result["total"] == 1
    assert result["items"][0].normalized_value == (
        "malicious.example.com"
    )


def test_list_iocs_pagination(session):
    for index in range(5):
        create_ioc(
            session,
            make_payload(f"192.0.2.{index + 10}"),
        )

    first_page = list_iocs(
        session,
        page=1,
        page_size=2,
    )

    second_page = list_iocs(
        session,
        page=2,
        page_size=2,
    )

    third_page = list_iocs(
        session,
        page=3,
        page_size=2,
    )

    assert first_page["total"] == 5
    assert first_page["total_pages"] == 3

    assert len(first_page["items"]) == 2
    assert len(second_page["items"]) == 2
    assert len(third_page["items"]) == 1

    first_ids = {
        item.id for item in first_page["items"]
    }

    second_ids = {
        item.id for item in second_page["items"]
    }

    assert first_ids.isdisjoint(second_ids)


def test_list_iocs_empty_database(session):
    result = list_iocs(session)

    assert result["items"] == []
    assert result["total"] == 0
    assert result["total_pages"] == 0


def test_list_iocs_search_with_no_matches(session):
    create_ioc(session, make_payload("192.0.2.10"))

    result = list_iocs(
        session,
        search="not-found",
    )

    assert result["total"] == 0
    assert result["items"] == []


# ---------------------------------------------------------
# DELETE TESTS
# ---------------------------------------------------------


def test_delete_ioc_successfully(session):
    created = create_ioc(
        session,
        make_payload(),
    )

    delete_ioc(session, created.id)

    result = session.scalar(
        select(IOC).where(IOC.id == created.id)
    )

    assert result is None


def test_delete_ioc_also_deletes_sources(session):
    created = create_ioc(
        session,
        make_payload(
            source_name="URLhaus",
            source_record_id="delete-001",
        ),
    )

    ioc_id = created.id

    source_count_before = session.scalar(
        select(func.count())
        .select_from(IOCSource)
        .where(IOCSource.ioc_id == ioc_id)
    )

    assert source_count_before == 1

    delete_ioc(session, ioc_id)

    source_count_after = session.scalar(
        select(func.count())
        .select_from(IOCSource)
        .where(IOCSource.ioc_id == ioc_id)
    )

    assert source_count_after == 0


def test_delete_missing_ioc_raises_error(session):
    with pytest.raises(IOCNotFoundError):
        delete_ioc(session, 99999)


# ---------------------------------------------------------
# TRANSACTION ROLLBACK TESTS
# ---------------------------------------------------------


def test_create_ioc_rolls_back_on_commit_failure(
    session,
    monkeypatch,
):
    def failing_commit():
        raise RuntimeError("Simulated database failure")

    monkeypatch.setattr(
        session,
        "commit",
        failing_commit,
    )

    with pytest.raises(
        RuntimeError,
        match="Simulated database failure",
    ):
        create_ioc(
            session,
            make_payload(),
        )

    count = session.scalar(
        select(func.count()).select_from(IOC)
    )

    assert count == 0


def test_delete_ioc_rolls_back_on_commit_failure(
    session,
    monkeypatch,
):
    created = create_ioc(
        session,
        make_payload(),
    )

    ioc_id = created.id

    def failing_commit():
        raise RuntimeError("Simulated database failure")

    monkeypatch.setattr(
        session,
        "commit",
        failing_commit,
    )

    with pytest.raises(
        RuntimeError,
        match="Simulated database failure",
    ):
        delete_ioc(session, ioc_id)

    monkeypatch.undo()

    session.expire_all()

    restored = get_ioc(session, ioc_id)

    assert restored.id == ioc_id
    assert len(restored.sources) == 1
