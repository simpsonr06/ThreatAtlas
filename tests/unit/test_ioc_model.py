
import pytest

from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

import app.models
from app.db import Base
from app.models import IOC, IOCSource


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(bind=engine)

    with Session(engine) as db:
        yield db

    engine.dispose()


def test_create_ioc(session):
    ioc = IOC(
        value="192.0.2.10",
        normalized_value="192.0.2.10",
        ioc_type="ip",
    )

    session.add(ioc)
    session.commit()

    assert ioc.id is not None
    assert ioc.ioc_type == "ip"


def test_duplicate_ioc_is_rejected(session):
    first = IOC(
        value="192.0.2.10",
        normalized_value="192.0.2.10",
        ioc_type="ip",
    )

    second = IOC(
        value="192.0.2.10",
        normalized_value="192.0.2.10",
        ioc_type="ip",
    )

    session.add(first)
    session.commit()

    session.add(second)

    with pytest.raises(IntegrityError):
        session.commit()

    session.rollback()


def test_ioc_can_have_multiple_sources(session):
    ioc = IOC(
        value="malicious.example",
        normalized_value="malicious.example",
        ioc_type="domain",
    )

    ioc.sources.extend([
        IOCSource(
            source_name="URLhaus",
            confidence=90.0,
        ),
        IOCSource(
            source_name="ThreatFox",
            confidence=85.0,
        ),
    ])

    session.add(ioc)
    session.commit()

    assert len(ioc.sources) == 2
    assert {source.source_name for source in ioc.sources} == {
        "URLhaus",
        "ThreatFox",
    }


def test_invalid_confidence_is_rejected(session):
    ioc = IOC(
        value="192.0.2.20",
        normalized_value="192.0.2.20",
        ioc_type="ip",
    )

    ioc.sources.append(
        IOCSource(
            source_name="URLhaus",
            confidence=150.0,
        )
    )

    session.add(ioc)

    with pytest.raises(IntegrityError):
        session.commit()

    session.rollback()
