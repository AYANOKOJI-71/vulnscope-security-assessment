from __future__ import annotations

from pathlib import Path

import yaml


def test_compose_keeps_the_safe_local_demo_contract() -> None:
    compose_path = Path(__file__).parents[1] / "docker-compose.yml"
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    services = compose["services"]

    assert {"postgres", "api", "web"}.issubset(services)
    assert "4700:4700" in services["api"]["ports"]
    assert services["api"]["environment"]["DEMO_MODE"] == "true"
    assert "5186:80" in services["web"]["ports"]
    assert services["api"]["depends_on"]["postgres"]["condition"] == "service_healthy"
