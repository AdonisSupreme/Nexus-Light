from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


if __package__ in {None, ""}:
    package_name = "nexus_light_agent"
    package_dir = Path(__file__).resolve().parent
    init_path = package_dir / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        package_name,
        init_path,
        submodule_search_locations=[str(package_dir)],
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to bootstrap {package_name} from {package_dir}")
    package = importlib.util.module_from_spec(spec)
    sys.modules[package_name] = package
    spec.loader.exec_module(package)
    __package__ = package_name

from .agent import NexusLightAgent, setup_logging
from .config import config_template, load_settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel Nexus light service agent")
    parser.add_argument("--config", help="Path to the agent JSON config file")
    parser.add_argument("--once", action="store_true", help="Run one collection cycle and exit")
    parser.add_argument("--validate-config", action="store_true", help="Validate config and exit")
    parser.add_argument("--print-config-template", action="store_true", help="Print a production config template")
    args = parser.parse_args(argv)

    if args.print_config_template:
        print(json.dumps(config_template(), indent=2))
        return 0

    if not args.config:
        parser.error("--config is required unless --print-config-template is used")

    settings = load_settings(args.config)
    if args.validate_config:
        settings.resolve_agent_token()
        print(
            json.dumps(
                {
                    "valid": True,
                    "agent_id": settings.agent_id,
                    "nexus_base_url": settings.nexus_base_url,
                    "services": [service.service_id for service in settings.enabled_services],
                },
                indent=2,
            )
        )
        return 0

    agent = NexusLightAgent(settings)
    if args.once:
        setup_logging(settings.log_file)
        agent.state.load()
        reports = agent.run_once()
        print(json.dumps({"reports": len(reports), "services": [r["service_id"] for r in reports]}, indent=2))
        return 0

    agent.run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
