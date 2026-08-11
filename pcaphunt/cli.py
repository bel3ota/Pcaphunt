"""CLI for PcapHunt."""

import argparse
import logging
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from pcaphunt.config import Config
from pcaphunt.engine import analyze_packets
from pcaphunt.output import get_counts, write_findings
from pcaphunt.version import __version__

BANNER = r"""[bold cyan]
 ____   ____          _   _             _
|  _ \ / ___|__ _ ___| | | |  _   _ _ __ | |_
| |_) | |   / _` / __| |_| | | | | | '_ \| __|
|  __/| |__| (_| \__ \  _  | | |_| | | | | |_
|_|    \____\__,_|___/_| |_|  \__,_|_| |_|\__|

             PCAP Content Hunter
[/bold cyan]"""


def get_parser() -> argparse.ArgumentParser:
    """Create and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="pcaphunt",
        description="PcapHunt - Hunt for useful data in PCAP/PCAPNG files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("pcap", nargs="?", help="Path to PCAP/PCAPNG file")
    parser.add_argument(
        "-o", "--output", default="./pcaphunt_output", help="Output directory (default: ./pcaphunt_output)"
    )
    parser.add_argument(
        "--deep", action="store_true", help="Enable deep mode (TCP stream reassembly, etc.)"
    )
    parser.add_argument(
        "--min-length", type=int, default=6, help="Minimum plaintext string length (default: 6)"
    )
    parser.add_argument(
        "--no-dedup", action="store_true", help="Disable deduplication"
    )
    parser.add_argument(
        "--json", action="store_true", help="Output findings as JSON to stdout"
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Suppress terminal output"
    )
    parser.add_argument(
        "--search", type=str, default="", help="Filter findings by search string"
    )
    parser.add_argument(
        "--version", action="store_true", help="Show version and exit"
    )
    return parser


def run_cli() -> int:
    """Run the CLI and return exit code.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    parser = get_parser()
    args = parser.parse_args()

    if args.version:
        print(__version__)
        return 0

    if not args.pcap:
        parser.print_help()
        return 1

    console = Console(quiet=args.quiet)
    console.print(BANNER)

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        console.print(f"[bold red]Error:[/bold red] PCAP file not found: {args.pcap}")
        return 1

    console.print(f"[cyan][*] Input:[/cyan] {args.pcap}")

    config = Config()
    config.set("min_length", args.min_length)
    config.set("output_directory", args.output)
    config.set("deduplication", not args.no_dedup)

    try:
        from scapy.all import rdpcap
        packets = rdpcap(str(pcap_path))
        total_packets = len(packets)
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] Failed to read PCAP: {exc}")
        return 1

    console.print(f"[cyan][*] Packets:[/cyan] {total_packets:,}")
    console.print("")

    start_time = time.time()
    all_findings: list[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
        transient=True,
    ) as progress:
        if args.deep:
            task = progress.add_task("[cyan]Deep analysis...", total=total_packets)
        else:
            task = progress.add_task("[cyan]Analyzing packets...", total=total_packets)

        def progress_callback(current: int, total: int) -> None:
            if total > 0:
                progress.update(task, completed=current, total=total)

        all_findings = analyze_packets(
            str(pcap_path),
            config,
            deep=args.deep,
            progress_callback=progress_callback,
        )

    # Filter by search string if provided
    if args.search:
        search_lower = args.search.lower()
        all_findings = [
            f for f in all_findings
            if search_lower in str(f.get("original", "")).lower()
            or search_lower in str(f.get("decoded", "")).lower()
            or search_lower in str(f.get("notes", "")).lower()
        ]

    elapsed = time.time() - start_time

    # Write output files
    if not args.json:
        write_findings(all_findings, args.output, deduplicate=not args.no_dedup)

    # Terminal output
    if not args.quiet:
        _print_results(console, all_findings, elapsed, args.output)

    if args.json:
        import json
        print(json.dumps(all_findings, indent=2, ensure_ascii=False, default=str))

    return 0


def _print_results(
    console: Console,
    findings: list[dict],
    elapsed: float,
    output_dir: str,
) -> None:
    """Print results to console.

    Args:
        console: Rich console.
        findings: List of findings.
        elapsed: Elapsed time in seconds.
        output_dir: Output directory path.
    """
    counts = get_counts(findings)

    console.print("[bold]────────────────────────────────────────────[/bold]")
    console.print("[bold cyan]              PCAPHUNT RESULTS[/bold cyan]")
    console.print("[bold]────────────────────────────────────────────[/bold]")
    console.print("")

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Type", style="cyan", justify="left")
    table.add_column("Count", style="white", justify="right")

    order = [
        "plaintext", "base64", "hex", "url_encoded", "urls",
        "ip_addresses", "domains", "emails", "credentials", "flags",
        "hashes", "jwt", "files", "suspicious",
    ]

    for ftype in order:
        count = counts.get(ftype, 0)
        label = ftype.replace("_", " ").title()
        table.add_row(label, str(count))

    other = sum(v for k, v in counts.items() if k not in order)
    if other:
        table.add_row("Other", str(other))

    console.print(table)
    console.print("")
    console.print("[bold]────────────────────────────────────────────[/bold]")
    console.print("")

    # Show flags prominently
    flags = [f for f in findings if f.get("type") == "flags"]
    if flags:
        console.print("[bold yellow]🏁 FLAGS FOUND:[/bold yellow]")
        for f in flags:
            decoded = f.get("decoded") or f.get("original")
            console.print(f"  [bold green]{decoded}[/bold green]")
        console.print("")

    # Credentials count (without exposing values)
    cred_count = counts.get("credentials", 0)
    if cred_count > 0:
        console.print(f"[bold yellow]🔒 Credentials detected: {cred_count}[/bold yellow]")
        console.print("  (saved to output/credentials/)")
        console.print("")

    console.print(f"[green][+] Results:[/green] {output_dir}/")
    console.print(f"[green][+] Analysis completed in {elapsed:.2f} seconds[/green]")


def main() -> None:
    """Entry point for pcaphunt CLI."""
    sys.exit(run_cli())


if __name__ == "__main__":
    main()
