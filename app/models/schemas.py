from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class PolarCustomer(BaseModel):
    id: str
    external_id: Optional[str] = None


class PolarSubscription(BaseModel):
    id: str
    status: str
    product_id: str
    customer_id: str
    created_at: datetime
    modified_at: Optional[datetime] = None
    current_period_end: Optional[datetime] = None
    cancel_at_period_end: bool = False
    metadata: Dict[str, Any] = {}
    customer: Optional[PolarCustomer] = None


class PolarSubscriptionEvent(BaseModel):
    type: str
    data: PolarSubscription


class AgentCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    agent_name: str = Field(min_length=1, max_length=100)


class AgentCreated(BaseModel):
    id: str
    agent_name: str
    token: str = Field(description="Shown once; only its SHA-256 hash is stored.")


class VaultKeyCreate(BaseModel):
    service_name: str
    raw_api_key: SecretStr


class VaultKeyStored(BaseModel):
    service_name: str
    status: str = "stored"
