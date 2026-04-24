"""
Mock MCP Server for Integration Testing

Simulates NotebookLM and other MCP tool servers for testing AI Guardian
protections without requiring actual external MCP servers.
"""

import json
from typing import Dict, Any, Optional, List


class MockMCPServer:
    """
    Mock MCP server that simulates NotebookLM and other MCP tools.

    Provides controllable responses for testing success and failure scenarios.
    """

    def __init__(self):
        """Initialize mock MCP server state."""
        self.notebooks = {}  # {notebook_id: {title, sources}}
        self.next_notebook_id = 1
        self.next_source_id = 1
        self.fail_next_call = False
        self.custom_response = None

    def reset(self):
        """Reset server state for clean test isolation."""
        self.notebooks = {}
        self.next_notebook_id = 1
        self.next_source_id = 1
        self.fail_next_call = False
        self.custom_response = None

    def set_fail_next_call(self, should_fail: bool = True):
        """Configure next call to fail (for testing error handling)."""
        self.fail_next_call = should_fail

    def set_custom_response(self, response: Any):
        """Set custom response for next call (for testing specific scenarios)."""
        self.custom_response = response

    # NotebookLM Tool Implementations

    def notebook_create(self, title: str, sources: Optional[List[Dict]] = None) -> Dict[str, Any]:
        """
        Simulate notebook_create tool.

        Args:
            title: Notebook title
            sources: Optional list of initial sources

        Returns:
            Dict with notebook_id and status
        """
        if self.fail_next_call:
            self.fail_next_call = False
            return {"error": "Failed to create notebook", "status": "error"}

        if self.custom_response is not None:
            response = self.custom_response
            self.custom_response = None
            return response

        notebook_id = f"nb_{self.next_notebook_id}"
        self.next_notebook_id += 1

        self.notebooks[notebook_id] = {
            "title": title,
            "sources": sources or [],
            "created": True
        }

        return {
            "notebook_id": notebook_id,
            "title": title,
            "status": "success"
        }

    def source_add(self, notebook_id: str, source_type: str,
                   url: Optional[str] = None, text: Optional[str] = None,
                   title: Optional[str] = None) -> Dict[str, Any]:
        """
        Simulate source_add tool.

        Args:
            notebook_id: Target notebook ID
            source_type: "url" or "text"
            url: URL for url type sources
            text: Text content for text type sources
            title: Optional source title

        Returns:
            Dict with source_id and status
        """
        if self.fail_next_call:
            self.fail_next_call = False
            return {"error": "Failed to add source", "status": "error"}

        if self.custom_response is not None:
            response = self.custom_response
            self.custom_response = None
            return response

        if notebook_id not in self.notebooks:
            return {"error": f"Notebook {notebook_id} not found", "status": "error"}

        source_id = f"src_{self.next_source_id}"
        self.next_source_id += 1

        source = {
            "source_id": source_id,
            "type": source_type,
            "title": title or f"Source {source_id}"
        }

        if source_type == "url":
            source["url"] = url
        elif source_type == "text":
            source["text"] = text

        self.notebooks[notebook_id]["sources"].append(source)

        return {
            "source_id": source_id,
            "notebook_id": notebook_id,
            "status": "success"
        }

    def notebook_query(self, notebook_id: str, query: str) -> Dict[str, Any]:
        """
        Simulate notebook_query tool.

        Args:
            notebook_id: Notebook to query
            query: Query string

        Returns:
            Dict with answer and sources
        """
        if self.fail_next_call:
            self.fail_next_call = False
            return {"error": "Query failed", "status": "error"}

        if self.custom_response is not None:
            response = self.custom_response
            self.custom_response = None
            return response

        if notebook_id not in self.notebooks:
            return {"error": f"Notebook {notebook_id} not found", "status": "error"}

        # Simulate a generic response
        return {
            "answer": f"Mock answer for query: {query}",
            "sources": self.notebooks[notebook_id]["sources"],
            "status": "success"
        }

    def notebook_list(self) -> Dict[str, Any]:
        """
        Simulate notebook_list tool.

        Returns:
            Dict with list of notebooks
        """
        if self.fail_next_call:
            self.fail_next_call = False
            return {"error": "Failed to list notebooks", "status": "error"}

        if self.custom_response is not None:
            response = self.custom_response
            self.custom_response = None
            return response

        notebooks = [
            {
                "notebook_id": nb_id,
                "title": nb_data["title"],
                "source_count": len(nb_data["sources"])
            }
            for nb_id, nb_data in self.notebooks.items()
        ]

        return {
            "notebooks": notebooks,
            "count": len(notebooks),
            "status": "success"
        }

    def notebook_delete(self, notebook_id: str) -> Dict[str, Any]:
        """
        Simulate notebook_delete tool.

        Args:
            notebook_id: Notebook to delete

        Returns:
            Dict with status
        """
        if self.fail_next_call:
            self.fail_next_call = False
            return {"error": "Failed to delete notebook", "status": "error"}

        if self.custom_response is not None:
            response = self.custom_response
            self.custom_response = None
            return response

        if notebook_id not in self.notebooks:
            return {"error": f"Notebook {notebook_id} not found", "status": "error"}

        del self.notebooks[notebook_id]

        return {
            "notebook_id": notebook_id,
            "status": "success"
        }

    # Generic Tool Execution

    def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generic tool execution simulator for any MCP tool.

        Args:
            tool_name: Full MCP tool name (e.g., "mcp__notebooklm-mcp__notebook_create")
            params: Tool parameters

        Returns:
            Dict with tool response
        """
        if self.fail_next_call:
            self.fail_next_call = False
            return {"error": f"Tool {tool_name} failed", "status": "error"}

        if self.custom_response is not None:
            response = self.custom_response
            self.custom_response = None
            return response

        # Extract tool method from full name
        # e.g., "mcp__notebooklm-mcp__notebook_create" -> "notebook_create"
        if "__" in tool_name:
            method_name = tool_name.split("__")[-1]
        else:
            method_name = tool_name

        # Route to specific method if it exists
        if hasattr(self, method_name):
            method = getattr(self, method_name)
            try:
                return method(**params)
            except TypeError as e:
                return {"error": f"Invalid parameters for {method_name}: {e}", "status": "error"}

        # Generic successful response for unknown tools
        return {
            "tool": tool_name,
            "params": params,
            "status": "success",
            "result": "Mock execution successful"
        }


def create_hook_data(tool_name: str, tool_input: Dict[str, Any],
                     hook_event: str = "PreToolUse") -> Dict[str, Any]:
    """
    Helper function to create hook data for testing.

    Args:
        tool_name: Tool name (e.g., "mcp__notebooklm-mcp__notebook_create")
        tool_input: Tool input parameters
        hook_event: "PreToolUse", "PostToolUse", or "UserPromptSubmit"

    Returns:
        Dict ready to be passed to AI Guardian hook processing
    """
    hook_data = {
        "hook_event_name": hook_event,
        "tool_name": tool_name,
    }

    if hook_event == "PreToolUse":
        hook_data["tool_input"] = tool_input
    elif hook_event == "PostToolUse":
        # For PostToolUse, tool_input becomes tool_response
        hook_data["tool_response"] = tool_input
    elif hook_event == "UserPromptSubmit":
        # For UserPromptSubmit, include user_prompt
        hook_data["user_prompt"] = tool_input.get("prompt", "")

    return hook_data


def create_tool_response(tool_name: str, output: Any) -> Dict[str, Any]:
    """
    Helper function to create PostToolUse hook data.

    Args:
        tool_name: Tool name
        output: Tool output (can be dict, string, etc.)

    Returns:
        Dict ready to be passed to AI Guardian PostToolUse processing
    """
    return {
        "hook_event_name": "PostToolUse",
        "tool_name": tool_name,
        "tool_response": output if isinstance(output, dict) else {"output": output}
    }
