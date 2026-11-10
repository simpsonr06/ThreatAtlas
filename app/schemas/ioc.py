
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


IOCType = Literal["ip", "domain", "url", "file_hash"]


class IOCSourceCreate(BaseModel):
    source_name: str = Field(
        default="manual",
        min_length=1,
        max_length=100,
    )

    source_record_id: str | None = Field(
        default=None,
        max_length=255,
    )

    source_url: str | None = Field(
        default=None,
        max_length=2048,
    )

    confidence: float = Field(
        default=50.0,
        ge=0,
        le=100,
    )

    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @field_validator("source_name")
    @classmethod
    def validate_source_name(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Source name cannot be empty")

        return value


class IOCCreate(BaseModel):
    value: str = Field(
        min_length=1,
        max_length=2048,
    )

    ioc_type: IOCType | None = None

    source: IOCSourceCreate = Field(
        default_factory=IOCSourceCreate
    )

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("IOC value cannot be empty")

        return value


class IOCSourceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source_name: str
    source_record_id: str | None
    source_url: str | None
    confidence: float
    first_seen: datetime | None
    last_seen: datetime | None
    ingested_at: datetime


class IOCResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    value: str
    normalized_value: str
    ioc_type: IOCType
    first_seen: datetime | None
    last_seen: datetime | None
    created_at: datetime
    updated_at: datetime
    sources: list[IOCSourceResponse] = Field(
        default_factory=list
    )


class IOCListResponse(BaseModel):
    items: list[IOCResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
