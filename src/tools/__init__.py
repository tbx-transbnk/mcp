"""MCP tool implementations - plain functions server.py wraps with @mcp.tool."""

from src.tools.accounts import get_balances, list_accounts
from src.tools.dashboard import dashboard_stats
from src.tools.transactions import credit_debit_summary, list_transactions, transaction_summary

__all__ = [
    "list_accounts",
    "get_balances",
    "list_transactions",
    "transaction_summary",
    "credit_debit_summary",
    "dashboard_stats",
]
