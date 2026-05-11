#!/usr/bin/env python3
"""
Nezel OSINT - authorized lookup helper.

Use only on phone numbers / vehicle records you own or are legally allowed to check.
Sensitive identity values returned by upstream APIs are masked before display.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
from typing import Any

import requests
from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text


console = Console()
TIMEOUT_SECONDS = 18


_PHONE_TEMPLATE_B64 = (
    "aHR0cHM6Ly9hcGkudmVjdG9yeG8ub25saW5lL2xvb2t1cD9rZXk9dmVjdG9yeG8mbW9iaWxlPXt0ZXJtfQ=="
)
_VEHICLE_TEMPLATE_B64 = (
    "aHR0cHM6Ly96eC1vc2ludC1naG9zdHhzaGF1cnlhLnZlcmNlbC5hcHAvYXBpP2tleT16eG9wJnR5cGU9cmMmdGVybT17dGVybX0="
)

SENSITIVE_KEYS = {
    "aadhaar",
    "aadhar",
    "adhar",
    "uid",
    "uidai",
    "id",
    "identity",
    "document",
    "doc",
    "card",
    "cardno",
    "card_no",
}

DISPLAY_LABELS = {
    "id": "Aadhaar No",
}


def decode_template(env_name: str, fallback_b64: str) -> str:
    configured = os.getenv(env_name)
    if configured:
        return configured
    return base64.b64decode(fallback_b64).decode("utf-8")


def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def banner() -> None:
    clear()
    art = r"""
 _   _               _    ___  ____ ___ _   _ _____
| \ | | ___ _______ | |  / _ \/ ___|_ _| \ | |_   _|
|  \| |/ _ \_  / _ \| | | | | \___ \| ||  \| | | |
| |\  |  __// /  __/| | | |_| |___) | || |\  | | |
|_| \_|\___/___\___||_|  \___/|____/___|_| \_| |_|
"""
    title = Text(art, style="bold cyan")
    subtitle = Text(
        "Authorized intelligence console | fast lookup | protected output",
        style="bright_green",
    )
    console.print(Align.center(title))
    console.print(Align.center(subtitle))
    console.print()


def menu() -> str:
    table = Table(box=box.ROUNDED, border_style="cyan", show_header=False, width=72)
    table.add_column("Key", style="bold bright_green", width=8, justify="center")
    table.add_column("Option", style="bold white")
    table.add_row("1", "Reverse phone number lookup")
    table.add_row("2", "Vehicle information gather")
    table.add_row("3", "Documentation")
    table.add_row("0", "Exit")
    console.print(Align.center(table))
    return Prompt.ask("[bold cyan]Select option[/bold cyan]", choices=["1", "2", "3", "0"])


def normalize_phone(raw: str) -> str | None:
    digits = re.sub(r"\D", "", raw)
    if digits.startswith("91") and len(digits) == 12:
        digits = digits[2:]
    if len(digits) == 10 and digits[0] in "6789":
        return digits
    return None


def normalize_vehicle(raw: str) -> str | None:
    value = re.sub(r"[^A-Za-z0-9]", "", raw).upper()
    if 6 <= len(value) <= 12:
        return value
    return None


def is_sensitive_key(key: str) -> bool:
    cleaned = re.sub(r"[^a-z0-9_]", "", key.lower())
    return any(marker in cleaned for marker in SENSITIVE_KEYS)


def mask_value(value: Any) -> str:
    text = str(value)
    if len(text) <= 4:
        return "*" * len(text)
    return f"{text[:2]}{'*' * max(4, len(text) - 4)}{text[-2:]}"


def sanitize(value: Any, parent_key: str = "") -> Any:
    if isinstance(value, dict):
        return {str(k): sanitize(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(item, parent_key) for item in value]
    if parent_key and is_sensitive_key(parent_key):
        return mask_value(value)
    return value


def flatten(value: Any, prefix: str = "") -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            next_prefix = f"{prefix}.{key}" if prefix else str(key)
            rows.extend(flatten(item, next_prefix))
    elif isinstance(value, list):
        if not value:
            rows.append((prefix, "[]"))
        for index, item in enumerate(value, 1):
            rows.extend(flatten(item, f"{prefix}[{index}]"))
    else:
        rows.append((prefix or "value", str(value)))
    return rows


def display_label(key: str) -> str:
    plain_key = key.split(".")[-1]
    plain_key = re.sub(r"\[\d+\]$", "", plain_key)
    return DISPLAY_LABELS.get(plain_key.lower(), key)


def request_json(template: str, term: str) -> Any:
    url = template.format(term=term)
    response = requests.get(url, timeout=TIMEOUT_SECONDS)
    response.raise_for_status()
    try:
        return response.json()
    except json.JSONDecodeError:
        return {"raw_response": response.text}


def show_result(title: str, term: str, payload: Any) -> None:
    safe_payload = sanitize(payload)
    rows = flatten(safe_payload)

    table = Table(
        title=f"{title} :: {term}",
        box=box.SIMPLE_HEAVY,
        border_style="bright_cyan",
        header_style="bold bright_green",
        show_lines=True,
    )
    table.add_column("Field", style="bold cyan", overflow="fold", ratio=1)
    table.add_column("Value", style="white", overflow="fold", ratio=2)

    if rows:
        for key, value in rows:
            table.add_row(display_label(key), value)
    else:
        table.add_row("status", "No data returned")

    console.print()
    console.print(table)
    console.print(
        Panel(
            "[yellow]Sensitive data hide for security reasons only law enforcement can access it.[/yellow]",
            border_style="yellow",
            box=box.ROUNDED,
        )
    )


def phone_lookup() -> None:
    console.print(Panel("[bold]Reverse Phone Number Lookup[/bold]", border_style="cyan"))
    suffix = Prompt.ask("[bold green]Enter mobile number[/bold green] [cyan]+91[/cyan]")
    phone = normalize_phone(suffix)
    if not phone:
        console.print("[bold red]Invalid number. Enter a valid 10 digit Indian mobile number.[/bold red]")
        return

    template = decode_template("NEZEL_PHONE_API_TEMPLATE", _PHONE_TEMPLATE_B64)
    with console.status("[bold cyan]Fetching phone intelligence...[/bold cyan]", spinner="dots"):
        payload = request_json(template, phone)
    show_result("Phone Lookup", f"+91{phone}", payload)


def vehicle_lookup() -> None:
    console.print(Panel("[bold]Vehicle Information Gather[/bold]", border_style="cyan"))
    raw = Prompt.ask("[bold green]Enter vehicle number[/bold green]").strip()
    vehicle = normalize_vehicle(raw)
    if not vehicle:
        console.print("[bold red]Invalid vehicle number format.[/bold red]")
        return

    template = decode_template("NEZEL_VEHICLE_API_TEMPLATE", _VEHICLE_TEMPLATE_B64)
    with console.status("[bold cyan]Fetching vehicle intelligence...[/bold cyan]", spinner="dots"):
        payload = request_json(template, vehicle)
    show_result("Vehicle Lookup", vehicle, payload)


def documentation() -> None:
    text = """
[bold cyan]Nezel OSINT Documentation[/bold cyan]

This tool is createdby nitya matai the future hacker encrypted for security reasons use it own your own risk.

[bold]Options[/bold]
1. Reverse phone number lookup
2. Vehicle information gather
3. Documentation

[bold]Security Notes[/bold]
- Use only for your own data or with clear permission.
- API templates can be moved to environment variables:
  NEZEL_PHONE_API_TEMPLATE
  NEZEL_VEHICLE_API_TEMPLATE
- Python code cannot hide a usable API key perfectly from someone who can run/read it.
- Sensitive identity fields such as Aadhaar/ID values are masked in output.
"""
    console.print(Panel(text.strip(), border_style="bright_green", box=box.DOUBLE))


def pause() -> None:
    console.print()
    Prompt.ask("[dim]Press Enter to continue[/dim]", default="", show_default=False)


def main() -> int:
    while True:
        banner()
        choice = menu()
        console.print()
        try:
            if choice == "1":
                phone_lookup()
                pause()
            elif choice == "2":
                vehicle_lookup()
                pause()
            elif choice == "3":
                documentation()
                pause()
            elif choice == "0":
                console.print("[bold bright_green]Bye. Stay legal, stay sharp.[/bold bright_green]")
                return 0
        except requests.HTTPError as exc:
            console.print(f"[bold red]API error:[/bold red] {exc}")
            pause()
        except requests.RequestException as exc:
            console.print(f"[bold red]Network error:[/bold red] {exc}")
            pause()
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Interrupted.[/bold yellow]")
            return 130


if __name__ == "__main__":
    sys.exit(main())
