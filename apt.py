#!/usr/bin/env python3
"""
APT Intel Database — CLI

Single entry point for all database operations.

Usage:
    python apt.py                           # Interactive menu
    python apt.py <command> [subcommand] [args]
    python apt.py --help

Commands:
    rebuild     Full database rebuild from source files
    import      Add new IOCs, scans, reports incrementally
    query       Search & analyze the database
    recon       Enrich IPs, detect staging, find candidates
    validate    OSINT validation (Shodan, OTX, AbuseIPDB, VT, Censys)
    export      Export lightweight web DB for dashboard
    status      Quick database statistics
"""

import sys
import subprocess
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent / "scripts"

# Command → (script, description)
COMMANDS = {
    "rebuild":  ("rebuild.py",     "Full database rebuild"),
    "import":   ("import_data.py", "Add new IOCs, scans, reports"),
    "query":    ("query.py",       "Search & analyze the database"),
    "recon":    ("recon.py",       "Enrich IPs, detect staging, find candidates"),
    "validate": ("validate.py",    "OSINT validation (5 sources)"),
    "export":   ("export.py",      "Export web DB for dashboard"),
}

# Subcommand menus for interactive mode
SUBCOMMANDS = {
    "rebuild": [
        ("(no args)",    "Full rebuild with backup"),
        ("--no-backup",  "Rebuild without backup"),
        ("--skip-domains", "Skip large domain import"),
    ],
    "import": [
        ("iocs",              "Re-import all IOC files"),
        ("ipv4 <file>",       "Import IPv4 list"),
        ("domains <file>",    "Import domain list"),
        ("vulnscan <file.csv>", "Import vulnerability scan CSV"),
        ("apt-report <file>", "Import APT target report"),
        ("master <file>",     "Import master report"),
        ("stats",             "Show current counts"),
    ],
    "query": [
        ("stats",           "Full database statistics"),
        ("critical [N]",    "Top critical IPs"),
        ("coverage",        "Scan coverage by tier"),
        ("unscanned [tier]","Unscanned priority targets"),
        ("search <pattern>","Search IP across tables"),
        ("ip <address>",    "Full IP profile"),
        ("domains <pattern>","Search domain IOCs"),
        ("cves",            "List all tracked CVEs"),
        ("vulnscan <ip>",     "Vulnerability findings for IP"),
    ],
    "recon": [
        ("enrich-top [N]",       "Enrich top N critical IPs"),
        ("enrich-ip <IP>",       "Enrich single IP"),
        ("enrich-subnet <CIDR>", "Enrich all IPs in subnet"),
        ("detect-staging",       "Detect staging/relay servers"),
        ("find-candidates",      "Discover new candidates"),
        ("report",               "Show recon summary"),
    ],
    "validate": [
        ("queue [N]",          "Build validation queue"),
        ("run <source> [N]",   "Run source (shodan/otx/abuseipdb/virustotal/censys/all)"),
        ("check <IP>",         "Check single IP, all sources"),
        ("auto",               "Scheduled run (auto batch sizes)"),
        ("status",             "Validation coverage stats"),
        ("log [N]",            "Transaction log (last N entries, default 30)"),
        ("purge-log [days]",   "Delete log entries older than N days"),
    ],
    "export": [],
}


def run_script(command, args=None):
    """Run a script with args via subprocess."""
    script_file, _ = COMMANDS[command]
    script_path = SCRIPTS_DIR / script_file
    cmd = [sys.executable, str(script_path)] + (args or [])
    return subprocess.run(cmd).returncode


def show_help():
    """Show full help."""
    print(__doc__)
    print("Commands:\n")
    for name, (_, desc) in COMMANDS.items():
        print("  %-12s %s" % (name, desc))
    print("  %-12s %s" % ("status", "Quick database statistics"))
    print()
    print("Run 'python apt.py <command>' for subcommand details.")
    print("Run 'python apt.py' with no args for interactive menu.")


def show_submenu(command):
    """Show subcommand menu and get user choice."""
    _, desc = COMMANDS[command]
    subs = SUBCOMMANDS.get(command, [])

    if not subs:
        return []

    print("\n  %s — %s\n" % (command, desc))
    for i, (sub, subdesc) in enumerate(subs, 1):
        print("  %d  %-22s %s" % (i, sub, subdesc))

    print()
    choice = input("  Enter number, or type subcommand + args: ").strip()

    if not choice:
        return None

    # Number selection
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(subs):
            sub_name = subs[idx][0]
            # If subcommand needs arguments, prompt
            if "<" in sub_name:
                base = sub_name.split()[0]
                arg = input("  Enter argument for '%s': " % sub_name).strip()
                if arg:
                    return [base] + arg.split()
                return None
            elif sub_name.startswith("("):
                return []  # No args needed (e.g. rebuild)
            elif sub_name.startswith("--"):
                return [sub_name]
            else:
                # Check for optional args like [N]
                base = sub_name.split()[0]
                return [base]
        return None

    # Direct text input
    return choice.split()


def interactive_menu():
    """Show main interactive menu."""
    print("\n  APT Intel Database — CLI\n")

    items = list(COMMANDS.items()) + [("status", (None, "Quick database statistics"))]

    for i, (name, (_, desc)) in enumerate(items, 1):
        print("  %d  %-12s %s" % (i, name, desc))

    print("  %d  %-12s %s" % (len(items) + 1, "help", "Show all commands"))
    print("  %d  %-12s %s" % (len(items) + 2, "exit", "Quit"))
    print()

    choice = input("  Enter number or command name: ").strip().lower()

    if not choice or choice in ("exit", "quit", "q", str(len(items) + 2)):
        return 0

    if choice in ("help", str(len(items) + 1)):
        show_help()
        return 0

    # Resolve number to command name
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(items):
            choice = items[idx][0]
        else:
            print("  Invalid choice.")
            return 1

    # Status shortcut
    if choice == "status":
        return run_script("query", ["stats"])

    if choice not in COMMANDS:
        print("  Unknown command: %s" % choice)
        return 1

    # Show subcommand menu if applicable
    subs = SUBCOMMANDS.get(choice, [])
    if subs:
        args = show_submenu(choice)
        if args is None:
            print("  Cancelled.")
            return 0
        return run_script(choice, args)
    else:
        return run_script(choice)


def main():
    args = sys.argv[1:]

    # No args → interactive
    if not args:
        return interactive_menu()

    # Help
    if args[0] in ("--help", "-h", "help"):
        show_help()
        return 0

    # Status shortcut
    if args[0] == "status":
        return run_script("query", ["stats"])

    command = args[0]
    if command not in COMMANDS:
        print("Unknown command: %s" % command)
        print("Run 'python apt.py --help' for usage.")
        return 1

    # If no subcommand given but command has subcommands, show menu
    if len(args) == 1 and SUBCOMMANDS.get(command):
        sub_args = show_submenu(command)
        if sub_args is None:
            return 0
        return run_script(command, sub_args)

    # Pass remaining args to the script
    return run_script(command, args[1:])


if __name__ == "__main__":
    sys.exit(main() or 0)
