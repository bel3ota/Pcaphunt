"""CLI for PcapHunt."""

from __future__ import annotations

import argparse
import json
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
from pcaphunt.engine import analyze_packets, analyze_pcap
from pcaphunt.filters import FilterCriteria
from pcaphunt.output import get_counts, write_findings, write_full_output
from pcaphunt.report import generate_html_report
from pcaphunt.version import __version__

BANNER = r"""[bold cyan]
 ____                 _   _             _
|  _ \ ___ __ _ _ __ | | | |_   _ _ __ | |_
| |_) / __/ _` | '_ \| |_| | | | | '_ \| __|
|  __/ (_| (_| | |_) |  _  | |_| | | | | |_
|_|   \___\__,_| .__/|_| |_\__,_|_| |_\__|
               |_|
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
        "--deep", action="store_true", help="Enable deep mode (TCP/UDP stream reassembly, protocol extraction)"
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
    parser.add_argument(
        "--html", action="store_true", default=True, help="Generate HTML report (default: enabled)"
    )
    parser.add_argument(
        "--no-html", action="store_true", help="Disable HTML report generation"
    )
    parser.add_argument(
        "--pattern", type=str, action="append", dest="patterns",
        help="Add a custom flag regex pattern (can be used multiple times)"
    )
    # Phase 2 advanced filtering
    parser.add_argument(
        "--category", type=str, default="", help="Filter findings by category/type"
    )
    parser.add_argument(
        "--protocol", type=str, default="", help="Filter findings by protocol"
    )
    parser.add_argument(
        "--ip", type=str, default="", help="Filter findings by IP (source or destination)"
    )
    parser.add_argument(
        "--src-ip", type=str, default="", help="Filter findings by source IP"
    )
    parser.add_argument(
        "--dst-ip", type=str, default="", help="Filter findings by destination IP"
    )
    parser.add_argument(
        "--port", type=int, default=None, help="Filter findings by port"
    )
    parser.add_argument(
        "--severity", type=str, default="", help="Filter findings by minimum severity"
    )
    parser.add_argument(
        "--min-score", type=int, default=None, help="Filter findings by minimum score"
    )
    parser.add_argument(
        "--stream", type=str, default="", help="Filter findings by stream ID"
    )
    # Phase 2 file extraction
    parser.add_argument(
        "--no-extract", action="store_true", help="Disable file extraction"
    )
    # Phase 2 custom rules
    parser.add_argument(
        "--rules", type=str, default="", help="Path to custom rules YAML file"
    )
    # Phase 2 YARA
    parser.add_argument(
        "--yara", type=str, default="", help="Path to YARA rule file or directory"
    )
    return parser


def run_cli() -> int:
    """Run the CLI and return exit code."""
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
    config.set("extract_files", not args.no_extract)
    if args.patterns:
        existing = config.flag_patterns
        config.set("flag_patterns", existing + args.patterns)
    if args.rules:
        config.set("custom_rules", args.rules)
    if args.yara:
        config.set("yara_rules_path", args.yara)

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

    # Build filter criteria
    filter_criteria = FilterCriteria(
        search_text=args.search,
        category=args.category,
        protocol=args.protocol,
        ip=args.ip,
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        port=args.port,
        severity=args.severity,
        min_score=args.min_score,
        stream_id=args.stream,
    )

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

        result = analyze_pcap(
            str(pcap_path),
            config,
            deep=args.deep,
            progress_callback=progress_callback,
            filter_criteria=filter_criteria,
        )

    elapsed = time.time() - start_time
    all_findings = result.findings

    # Write output files
    if not args.json:
        write_full_output(result, args.output)

        # Generate HTML report unless disabled
        if args.html and not args.no_html:
            html_path = Path(args.output) / "report.html"
            generate_html_report(
                findings=all_findings,
                pcap_name=pcap_path.name,
                output_path=str(html_path),
                duration_seconds=elapsed,
                result=result,
            )
            if not args.quiet:
                console.print(f"[green][+] HTML report:[/green] {html_path}")

    # Terminal output
    if not args.quiet:
        _print_results(console, result, elapsed, args.output)

    if args.json:
        # Backwards-compatible: output findings list when --json is used
        print(json.dumps(all_findings, indent=2, ensure_ascii=False, default=str))

    return 0


def _print_results(
    console: Console,
    result,
    elapsed: float,
    output_dir: str,
) -> None:
    """Print results to console."""
    findings = result.findings
    counts = get_counts(findings)
    profile = result.profile

    console.print("[bold]────────────────────────────────────────────[/bold]")
    console.print("[bold cyan]              PcapHunt RESULTS[/bold cyan]")
    console.print("[bold]────────────────────────────────────────────[/bold]")
    console.print("")

    # Profile summary
    if profile:
        console.print(f"[cyan]Packets:[/cyan]        {profile.total_packets:,}")
        if profile.capture_duration_seconds > 0:
            dur_m = int(profile.capture_duration_seconds // 60)
            dur_s = int(profile.capture_duration_seconds % 60)
            console.print(f"[cyan]Duration:[/cyan]       {dur_m:02d}:{dur_s:02d}")
        console.print("")

    # Severity distribution
    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    if severity_counts:
        sev_order = ["critical", "high", "medium", "low", "info"]
        for sev in sev_order:
            if sev in severity_counts:
                color = {
                    "critical": "bold red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "cyan",
                    "info": "dim",
                }.get(sev, "white")
                console.print(f"[{color}]{sev.upper():12s}[/] {severity_counts[sev]:>6,}")
        console.print("")

    # Category counts
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
        if count > 0:
            label = ftype.replace("_", " ").title()
            table.add_row(label, str(count))

    other = sum(v for k, v in counts.items() if k not in order)
    if other:
        table.add_row("Other", str(other))

    if table.rows:
        console.print(table)
    console.print("")

    # Show flags prominently
    flags = [f for f in findings if f.get("type") == "flags"]
    if flags:
        console.print("[bold yellow]🏁 FLAGS FOUND:[/bold yellow]")
        for f in flags:
            decoded = f.get("decoded") or f.get("original")
            score_str = f" (score: {f.get('score', 0)})" if f.get("score", 0) > 0 else ""
            console.print(f"  [bold green]{decoded}[/bold green]{score_str}")
        console.print("")

    # Credentials count (without exposing values)
    cred_count = counts.get("credentials", 0)
    if cred_count > 0:
        console.print(f"[bold yellow]🔒 Credentials detected: {cred_count}[/bold yellow]")
        console.print("  (saved to output/credentials/)")
        console.print("")

    # Files extracted
    if result.artifacts:
        complete = sum(1 for a in result.artifacts if a.complete)
        total_files = len(result.artifacts)
        console.print(f"[bold cyan]📁 Files extracted: {complete}/{total_files} complete[/bold cyan]")
        console.print("  (saved to output/extracted_files/)")
        console.print("")

    # Protocol findings summary
    proto_findings = [f for f in findings if str(f.get("type", "")).startswith("protocol_")]
    if proto_findings:
        proto_counts: dict[str, int] = {}
        for pf in proto_findings:
            ptype = pf.get("type", "protocol_unknown")
            proto_counts[ptype] = proto_counts.get(ptype, 0) + 1
        console.print("[bold cyan]📡 Protocol Findings:[/bold cyan]")
        for ptype, count in sorted(proto_counts.items()):
            label = ptype.replace("protocol_", "").upper()
            console.print(f"  {label}: {count}")
        console.print("")

    # YARA matches
    if result.yara_matches:
        console.print(f"[bold magenta]🛡️ YARA matches: {len(result.yara_matches)}[/bold magenta]")
        console.print("")

    console.print(f"[green][+] Results:[/green] {output_dir}/")
    console.print(f"[green][+] Analysis completed in {elapsed:.2f} seconds[/green]")


def main() -> None:
    """Entry point for PcapHunt CLI."""
    sys.exit(run_cli())


if __name__ == "__main__":
    main()
