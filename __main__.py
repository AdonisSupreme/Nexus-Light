from __future__ import annotations

import argparse
import json
import sys

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
