from langchain_core.tools import tool

from cybersecurity_agent.agents.cti_agents.utils.system_manager import inventory

@tool
def find_relative_component(keyword: str):
    """Fast keyword search across all loaded inventories."""
    found_component = inventory.search(keyword)
    return found_component
