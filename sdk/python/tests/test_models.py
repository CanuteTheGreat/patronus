"""Tests for data models."""

import pytest
from datetime import datetime
from patronus.models import (
    Site,
    Tunnel,
    TunnelStatus,
    Policy,
    PolicyRule,
    Organization,
    MLModel,
)


def test_site_creation():
    """Test Site model creation."""
    site = Site(
        id="site-123",
        name="hq-site",
        location="New York",
        wan_interfaces=["eth0", "eth1"],
        created_at=datetime.now(),
        updated_at=datetime.now(),
    )

    assert site.id == "site-123"
    assert site.name == "hq-site"
    assert len(site.wan_interfaces) == 2


def test_tunnel_status():
    """Test TunnelStatus model."""
    status = TunnelStatus(
        state="up", latency_ms=10.5, packet_loss=0.01, bandwidth_mbps=100.0
    )

    assert status.state == "up"
    assert status.latency_ms == 10.5
    assert status.packet_loss == 0.01


def test_tunnel_creation():
    """Test Tunnel model creation."""
    tunnel = Tunnel(
        id="tunnel-123",
        name="hq-to-branch",
        local_site_id="site-1",
        remote_site_id="site-2",
        protocol="wireguard",
        status=TunnelStatus(state="up"),
        created_at=datetime.now(),
        updated_at=datetime.now(),
    )

    assert tunnel.id == "tunnel-123"
    assert tunnel.protocol == "wireguard"
    assert tunnel.status.state == "up"


def test_policy_rule():
    """Test PolicyRule model."""
    rule = PolicyRule(protocol="tcp", dst_port=443, action="allow", priority=10)

    assert rule.protocol == "tcp"
    assert rule.dst_port == 443
    assert rule.action == "allow"


def test_policy_creation():
    """Test Policy model creation."""
    rules = [
        PolicyRule(protocol="tcp", dst_port=443, action="allow", priority=10),
        PolicyRule(protocol="udp", dst_port=53, action="allow", priority=20),
    ]

    policy = Policy(
        id="policy-123",
        name="allow-web",
        rules=rules,
        enabled=True,
        created_at=datetime.now(),
        updated_at=datetime.now(),
    )

    assert policy.id == "policy-123"
    assert len(policy.rules) == 2
    assert policy.enabled is True


def test_organization_creation():
    """Test Organization model creation."""
    org = Organization(
        id="org-123",
        name="acme",
        display_name="Acme Corporation",
        subscription_tier="enterprise",
        created_at=datetime.now(),
        updated_at=datetime.now(),
    )

    assert org.id == "org-123"
    assert org.name == "acme"
    assert org.subscription_tier == "enterprise"


def test_ml_model_creation():
    """Test MLModel model creation."""
    model = MLModel(
        id="model-123",
        name="anomaly-detector",
        version="v1.0.0",
        model_type="anomaly_detection",
        status="deployed",
        accuracy=0.95,
        created_at=datetime.now(),
        deployed_at=datetime.now(),
    )

    assert model.id == "model-123"
    assert model.version == "v1.0.0"
    assert model.accuracy == 0.95
    assert model.status == "deployed"


def test_site_with_metadata():
    """Test Site with metadata."""
    site = Site(
        id="site-123",
        name="branch",
        location="Boston",
        wan_interfaces=["eth0"],
        metadata={"region": "us-east", "datacenter": "bos-1"},
        created_at=datetime.now(),
        updated_at=datetime.now(),
    )

    assert site.metadata["region"] == "us-east"
    assert site.metadata["datacenter"] == "bos-1"


def test_policy_rule_defaults():
    """Test PolicyRule default values."""
    rule = PolicyRule(action="allow")

    assert rule.action == "allow"
    assert rule.priority == 100
    assert rule.protocol is None
    assert rule.src_port is None
