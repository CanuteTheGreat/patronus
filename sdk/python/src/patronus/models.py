"""Data models for Patronus SDK."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class Site(BaseModel):
    """Represents a network site."""

    id: str
    name: str
    location: str
    wan_interfaces: List[str]
    created_at: datetime
    updated_at: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TunnelStatus(BaseModel):
    """Tunnel status information."""

    state: str  # "up", "down", "degraded"
    latency_ms: Optional[float] = None
    packet_loss: Optional[float] = None
    bandwidth_mbps: Optional[float] = None
    last_seen: Optional[datetime] = None


class Tunnel(BaseModel):
    """Represents a VPN tunnel."""

    id: str
    name: str
    local_site_id: str
    remote_site_id: str
    protocol: str  # "wireguard", "ipsec", "gre"
    status: TunnelStatus
    created_at: datetime
    updated_at: datetime


class PolicyRule(BaseModel):
    """Policy rule definition."""

    protocol: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    action: str  # "allow", "deny", "route"
    priority: int = 100


class Policy(BaseModel):
    """Routing/QoS policy."""

    id: str
    name: str
    description: Optional[str] = None
    rules: List[PolicyRule]
    site_id: Optional[str] = None
    enabled: bool = True
    created_at: datetime
    updated_at: datetime


class Organization(BaseModel):
    """Multi-tenant organization."""

    id: str
    name: str
    display_name: str
    subscription_tier: str  # "free", "starter", "professional", "enterprise"
    created_at: datetime
    updated_at: datetime


class MetricData(BaseModel):
    """Time-series metric data."""

    timestamp: datetime
    value: float
    labels: Dict[str, str] = Field(default_factory=dict)


class Metrics(BaseModel):
    """Collection of metrics."""

    metric_name: str
    data: List[MetricData]


class MLModel(BaseModel):
    """Machine learning model metadata."""

    id: str
    name: str
    version: str
    model_type: str  # "anomaly_detection", "predictive_failover", etc.
    status: str  # "training", "validated", "deployed", "archived"
    accuracy: Optional[float] = None
    created_at: datetime
    deployed_at: Optional[datetime] = None
