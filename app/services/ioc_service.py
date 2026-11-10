
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models import IOC, IOCSource
from app.schemas.ioc import IOCCreate, IOCType
from app.services.ioc_normalizer import normalize_ioc


class IOCNotFoundError(Exception):
    """Raised when an IOC does not exist."""


def create_ioc(db: Session, payload: IOCCreate) -> IOC:
    """
    Create an IOC or attach a new source to an existing IOC.

    IOC identity is based on its type and normalized value.
    Repeated submissions from the same source record are idempotent.
    """

    normalized = normalize_ioc(
        payload.value,
        payload.ioc_type,
    )

    try:
        statement = select(IOC).where(
            IOC.ioc_type == normalized.ioc_type,
            IOC.normalized_value == normalized.normalized_value,
        )

        ioc = db.scalar(statement)

        if ioc is None:
            ioc = IOC(
                value=normalized.original_value,
                normalized_value=normalized.normalized_value,
                ioc_type=normalized.ioc_type,
            )
            db.add(ioc)
            db.flush()

        source_data = payload.source

        source_statement = select(IOCSource).where(
            IOCSource.ioc_id == ioc.id,
            IOCSource.source_name == source_data.source_name,
        )

        if source_data.source_record_id is None:
            source_statement = source_statement.where(
                IOCSource.source_record_id.is_(None)
            )
        else:
            source_statement = source_statement.where(
                IOCSource.source_record_id
                == source_data.source_record_id
            )

        existing_source = db.scalar(source_statement)

        if existing_source is None:
            source = IOCSource(
                source_name=source_data.source_name,
                source_record_id=source_data.source_record_id,
                source_url=source_data.source_url,
                confidence=source_data.confidence,
                first_seen=source_data.first_seen,
                last_seen=source_data.last_seen,
            )
            ioc.sources.append(source)

        db.commit()

        result_statement = (
            select(IOC)
            .options(selectinload(IOC.sources))
            .where(IOC.id == ioc.id)
        )

        return db.scalar(result_statement)

    except Exception:
        db.rollback()
        raise


def get_ioc(db: Session, ioc_id: int) -> IOC:
    """Retrieve an IOC with its associated sources."""

    statement = (
        select(IOC)
        .options(selectinload(IOC.sources))
        .where(IOC.id == ioc_id)
    )

    ioc = db.scalar(statement)

    if ioc is None:
        raise IOCNotFoundError(
            f"IOC with ID {ioc_id} was not found"
        )

    return ioc


def list_iocs(
    db: Session,
    page: int = 1,
    page_size: int = 20,
    ioc_type: IOCType | None = None,
    search: str | None = None,
) -> dict:
    """Return paginated IOC records with optional filters."""

    filters = []

    if ioc_type is not None:
        filters.append(IOC.ioc_type == ioc_type)

    if search:
        search_term = search.strip()

        if search_term:
            filters.append(
                IOC.normalized_value.contains(
                    search_term,
                    autoescape=True,
                )
            )

    count_statement = (
        select(func.count())
        .select_from(IOC)
        .where(*filters)
    )

    total = db.scalar(count_statement) or 0

    statement = (
        select(IOC)
        .options(selectinload(IOC.sources))
        .where(*filters)
        .order_by(IOC.created_at.desc(), IOC.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )

    items = list(db.scalars(statement).all())

    total_pages = (
        (total + page_size - 1) // page_size
        if total
        else 0
    )

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


def delete_ioc(db: Session, ioc_id: int) -> None:
    """Delete an IOC and its associated sources."""

    ioc = get_ioc(db, ioc_id)

    try:
        db.delete(ioc)
        db.commit()
    except Exception:
        db.rollback()
        raise
