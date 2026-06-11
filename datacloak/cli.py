"""
DataCloak Command-Line Interface.

Usage::

    datacloak scan file.txt
    datacloak mask file.txt
    datacloak mask file.txt --mode full --output masked.txt
    datacloak report file.txt
    datacloak report file.txt --output report.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

import datacloak
from datacloak.file_scanner import mask_file, scan_file
from datacloak.masker import MaskMode
from datacloak.reporter import generate_report_from_file


# ---------------------------------------------------------------------------
# CLI root
# ---------------------------------------------------------------------------


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(datacloak.__version__, "-V", "--version")
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    default=False,
    help="Enable verbose logging output.",
)
def cli(verbose: bool) -> None:
    """
    \b
    DataCloak — Privacy Protection CLI
    ===================================
    Detect and mask PII in text files.
    """
    if verbose:
        import logging

        logging.basicConfig(
            level=logging.DEBUG,
            format="%(levelname)s %(name)s: %(message)s",
        )


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------


@cli.command("scan")
@click.argument("file", type=click.Path(exists=True, readable=True, path_type=Path))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "table"], case_sensitive=False),
    default="table",
    show_default=True,
    help="Output format.",
)
def scan_cmd(file: Path, output_format: str) -> None:
    """
    Scan FILE for PII and display findings.

    \b
    Examples:
      datacloak scan customer_data.txt
      datacloak scan --format json logs.txt
    """
    result = scan_file(file)

    if result.error:
        click.secho(f"Error: {result.error}", fg="red", err=True)
        sys.exit(1)

    if not result.findings:
        click.secho("✓ No PII detected.", fg="green")
        return

    if output_format == "json":
        click.echo(json.dumps(result.by_type, indent=2, ensure_ascii=False))
        return

    # Table output
    click.secho(f"\n📄 File: {file}", bold=True)
    click.secho(f"{'PII Type':<18} {'Value':<40} {'Line':>6}", fg="cyan")
    click.secho("─" * 66, fg="cyan")
    for finding in result.findings:
        line_str = str(finding.line_number) if finding.line_number else "—"
        click.echo(f"{finding.pii_type:<18} {finding.value:<40} {line_str:>6}")

    click.secho("─" * 66, fg="cyan")
    click.secho(f"\nSummary: {result.summary}", fg="yellow")
    risk_colours = {"NONE": "green", "LOW": "yellow", "MEDIUM": "magenta", "HIGH": "red"}
    from datacloak.reporter import _risk_level

    risk = _risk_level(len(result.findings))
    colour = risk_colours.get(risk, "white")
    click.secho(f"Risk level: {risk}", fg=colour, bold=True)


# ---------------------------------------------------------------------------
# mask command
# ---------------------------------------------------------------------------


@cli.command("mask")
@click.argument("file", type=click.Path(exists=True, readable=True, path_type=Path))
@click.option(
    "-m",
    "--mode",
    type=click.Choice(["partial", "full", "hash"], case_sensitive=False),
    default="partial",
    show_default=True,
    help="Masking mode.",
)
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Output file path (default: <file>.masked<ext>).",
)
@click.option(
    "--stdout",
    is_flag=True,
    default=False,
    help="Print masked output to stdout instead of writing a file.",
)
def mask_cmd(file: Path, mode: str, output_path: Path | None, stdout: bool) -> None:
    """
    Mask PII in FILE.

    \b
    Masking modes:
      partial  Keep last characters visible (default)
      full     Replace with descriptive tags, e.g. [EMAIL_REDACTED]
      hash     Replace with SHA-256 digest

    \b
    Examples:
      datacloak mask logs.txt
      datacloak mask logs.txt --mode full --output clean_logs.txt
      datacloak mask logs.txt --stdout | less
    """
    if stdout:
        content = file.read_text(encoding="utf-8", errors="replace")
        from datacloak.masker import mask_text

        click.echo(mask_text(content, mode=mode))  # type: ignore[arg-type]
        return

    dest = mask_file(file, output_path=output_path, mode=mode)  # type: ignore[arg-type]
    click.secho(f"✓ Masked file written to: {dest}", fg="green")


# ---------------------------------------------------------------------------
# report command
# ---------------------------------------------------------------------------


@cli.command("report")
@click.argument("file", type=click.Path(exists=True, readable=True, path_type=Path))
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Save report as JSON to this path.",
)
@click.option(
    "--pretty",
    is_flag=True,
    default=True,
    help="Pretty-print JSON output (default: True).",
)
def report_cmd(file: Path, output_path: Path | None, pretty: bool) -> None:
    """
    Generate a PII scan report for FILE.

    \b
    Examples:
      datacloak report data.txt
      datacloak report data.csv --output report.json
    """
    rep = generate_report_from_file(file)

    json_str = rep.to_json(indent=2 if pretty else None)

    if output_path:
        rep.save(output_path)
        click.secho(f"✓ Report saved to: {output_path}", fg="green")
    else:
        click.echo(json_str)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
