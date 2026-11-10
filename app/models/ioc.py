
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class IOC(Base):
    __tablename__ = "iocs"

    __table_args__ = (
        UniqueConstraint(
            "ioc_type",
            "normalized_value",
            name="uq_ioc_type_normalized_value",
        ),
        CheckConstraint(
            "ioc_type IN ('ip', 'domain', 'url', 'file_hash')",
            name="ck_ioc_type_valid",
        ),
        Index(
            "ix_iocs_ioc_type",
            "ioc_type",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    value: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
    )

    normalized_value: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
    )

    ioc_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    sources: Mapped[list["IOCSource"]] = relationship(
        back_populates="ioc",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class IOCSource(Base):
    __tablename__ = "ioc_sources"

    __table_args__ = (
        CheckConstraint(
            "confidence >= 0 AND confidence <= 100",
            name="ck_ioc_source_confidence",
        ),
        Index(
            "ix_ioc_sources_source_name",
            "source_name",
        ),
        Index(
            "uq_ioc_source_record",
            "ioc_id",
            "source_name",
            "source_record_id",
            unique=True,
            sqlite_where=text("source_record_id IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    ioc_id: Mapped[int] = mapped_column(
        ForeignKey("iocs.id", ondelete="CASCADE"),
        nullable=False,
    )

    source_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    source_record_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    source_url: Mapped[str | None] = mapped_column(
        String(2048),
        nullable=True,
    )

    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=50.0,
    )

    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    ioc: Mapped["IOC"] = relationship(
        back_populates="sources",
    )
