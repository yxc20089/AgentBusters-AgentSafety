#!/usr/bin/env python3
"""
Scenario Plugin Registry

Maps scenario type names to plugin implementations and provides
a factory function to load scenario plugins from configuration.
"""

from typing import Any

from .base import ScenarioPlugin
from .portfolioiq import PortfolioIQPlugin
from .thingularity import ThingularityPlugin
from .example_medical import MedicalRecordsPlugin


# Registry mapping scenario names to plugin classes
# Note: Team submissions use string paths for lazy loading to avoid circular imports
SCENARIO_PLUGINS: dict[str, type[ScenarioPlugin] | str] = {
    "portfolioiq": PortfolioIQPlugin,
    "thingularity": ThingularityPlugin,
    "medical_records": MedicalRecordsPlugin,  # Example custom scenario
    # Team submissions (lazy loaded)
    "configforge": "scenarios.security_arena.submissions.AgentBusters.configforge.plugin:ConfigForgePlugin",
    "therapytrap": "scenarios.security_arena.submissions.AgentBusters.therapytrap.plugin:TherapyTrapPlugin",
    "therapytokentrap": "scenarios.security_arena.submissions.AgentBusters.therapytokentrap.plugin:TherapyTokenTrapPlugin",
    "inductive_backdoor": "scenarios.security_arena.submissions.AgentBusters.inductive_backdoor_in_finetuning.plugin:InductiveBackdoorPlugin",
    "copyrightcat": "scenarios.security_arena.submissions.AgentBusters.copyrightcat.plugin:CopyrightCatPlugin",
    "stockbotspoof": "scenarios.security_arena.submissions.AgentBusters.stockbotspoof.plugin:StockBotSpoofPlugin",
    "tickettwister": "scenarios.security_arena.submissions.AgentBusters.tickettwister.plugin:TicketTwisterPlugin",
}


def _resolve_plugin_class(plugin_ref: type[ScenarioPlugin] | str) -> type[ScenarioPlugin]:
    """
    Resolve a plugin reference to an actual class.

    Supports both direct class references and lazy loading via import strings.
    Import string format: "module.path:ClassName"
    """
    if isinstance(plugin_ref, str):
        # Lazy loading: "module.path:ClassName"
        import importlib
        module_path, class_name = plugin_ref.rsplit(":", 1)
        module = importlib.import_module(module_path)
        return getattr(module, class_name)
    return plugin_ref


def load_scenario(scenario_type: str, config: dict[str, Any]) -> ScenarioPlugin:
    """
    Load a scenario plugin by type name.

    Args:
        scenario_type: The scenario type from config (e.g., "portfolioiq")
        config: Configuration dict for the scenario

    Returns:
        Instantiated scenario plugin

    Raises:
        ValueError: If scenario_type is not registered

    Example:
        >>> config = {
        ...     "scenario_type": "portfolioiq",
        ...     "expected_risk_level": "High",
        ...     "target_risk_level": "Low",
        ...     "document_path": "data/ponzicorp_base.json"
        ... }
        >>> scenario = load_scenario("portfolioiq", config)
        >>> print(scenario.get_attack_objective())
    """
    plugin_ref = SCENARIO_PLUGINS.get(scenario_type)

    if not plugin_ref:
        available = ", ".join(SCENARIO_PLUGINS.keys())
        raise ValueError(
            f"Unknown scenario type: '{scenario_type}'. "
            f"Available scenarios: {available}"
        )

    plugin_class = _resolve_plugin_class(plugin_ref)
    return plugin_class(config)


def list_scenarios() -> list[str]:
    """
    List all registered scenario types.

    Returns:
        List of scenario type names
    """
    return list(SCENARIO_PLUGINS.keys())


def register_scenario(name: str, plugin_class: type[ScenarioPlugin]) -> None:
    """
    Register a custom scenario plugin.

    This allows participants to add custom scenarios without modifying
    the core registry file.

    Args:
        name: Scenario type name (used in config)
        plugin_class: Plugin class implementing ScenarioPlugin

    Example:
        >>> class CustomPlugin(ScenarioPlugin):
        ...     # ... implement methods ...
        ...     pass
        >>> register_scenario("custom", CustomPlugin)
    """
    if name in SCENARIO_PLUGINS:
        raise ValueError(f"Scenario '{name}' is already registered")

    if not issubclass(plugin_class, ScenarioPlugin):
        raise TypeError(
            f"Plugin class must inherit from ScenarioPlugin, "
            f"got {plugin_class.__name__}"
        )

    SCENARIO_PLUGINS[name] = plugin_class
