"""OpenWorlds CLI — Command-line interface for the simulation engine.

Commands:
    openworlds manifest generate    Generate a new AD network manifest
    openworlds manifest show        Display manifest summary
    openworlds shell                Interactive shell against a manifest
    openworlds trajectory generate  Generate training trajectories
    openworlds train                Fine-tune a model on trajectories
    openworlds eval                 Evaluate a model's performance
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from openworlds import __version__

app = typer.Typer(
    name="openworlds",
    help="🌐 OpenWorlds — Simulation engine for agentic pentesting",
    add_completion=False,
)

manifest_app = typer.Typer(help="Manage AD network manifests")
trajectory_app = typer.Typer(help="Generate training trajectories")
app.add_typer(manifest_app, name="manifest")
app.add_typer(trajectory_app, name="trajectory")

console = Console()


# ---------------------------------------------------------------------------
# Manifest commands
# ---------------------------------------------------------------------------


@manifest_app.command("generate")
def manifest_generate(
    hosts: int = typer.Option(20, "--hosts", "-n", help="Number of hosts"),
    subnets: int = typer.Option(2, "--subnets", "-s", help="Number of subnets"),
    users: int = typer.Option(50, "--users", "-u", help="Number of users"),
    groups: int = typer.Option(15, "--groups", "-g", help="Number of groups"),
    seed: int = typer.Option(42, "--seed", help="Random seed for reproducibility"),
    output: Path = typer.Option(
        Path("data/manifests/default.json"),
        "--output", "-o",
        help="Output path for the manifest JSON",
    ),
    kerberoasting: bool = typer.Option(True, help="Include Kerberoasting paths"),
    asrep: bool = typer.Option(True, help="Include AS-REP Roasting paths"),
    acl_abuse: bool = typer.Option(True, help="Include ACL abuse chains"),
    adcs: bool = typer.Option(True, help="Include AD CS abuse paths"),
    share_creds: bool = typer.Option(True, help="Include credentials in shares"),
) -> None:
    """Generate a new AD network manifest with attack paths."""
    from openworlds.world_engine.ad_graph import ManifestGenerator
    from openworlds.world_engine.models import ManifestConfig
    from openworlds.world_engine.path_validator import PathValidator
    from openworlds.world_engine.vuln_injector import VulnerabilityInjector

    config = ManifestConfig(
        num_hosts=hosts,
        num_subnets=subnets,
        num_users=users,
        num_groups=groups,
        seed=seed,
        include_kerberoasting=kerberoasting,
        include_asrep_roasting=asrep,
        include_acl_abuse=acl_abuse,
        include_adcs_abuse=adcs,
        include_credential_in_shares=share_creds,
    )

    with console.status("[bold green]Generating AD network..."):
        # Step 1: Generate base network
        generator = ManifestGenerator(config)
        manifest = generator.generate()
        console.print("  ✅ Base network generated")

        # Step 2: Inject vulnerabilities
        injector = VulnerabilityInjector(manifest)
        injector.inject_all()
        console.print("  ✅ Vulnerabilities injected")

        # Step 3: Validate attack paths
        validator = PathValidator(manifest)
        paths = validator.find_attack_paths()
        manifest.attack_paths = paths
        console.print(f"  ✅ Found {len(paths)} attack path(s)")

    # Save manifest
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest_json = manifest.model_dump_json(indent=2)
    output.write_text(manifest_json)

    # Display summary
    _display_manifest_summary(manifest, output)


@manifest_app.command("show")
def manifest_show(
    manifest_path: Path = typer.Argument(
        ..., help="Path to the manifest JSON file"
    ),
) -> None:
    """Display a summary of an existing manifest."""
    from openworlds.world_engine.models import Manifest

    if not manifest_path.exists():
        console.print(f"[red]Error:[/] Manifest not found: {manifest_path}")
        raise typer.Exit(1)

    manifest_data = json.loads(manifest_path.read_text())
    manifest = Manifest.model_validate(manifest_data)
    _display_manifest_summary(manifest, manifest_path)


# ---------------------------------------------------------------------------
# Shell command (interactive exploration)
# ---------------------------------------------------------------------------


@app.command("shell")
def interactive_shell(
    manifest_path: Path = typer.Option(
        Path("data/manifests/default.json"),
        "--manifest", "-m",
        help="Path to the manifest JSON",
    ),
) -> None:
    """Launch an interactive shell to explore the simulated network."""
    from openworlds.world_engine.models import Manifest

    if not manifest_path.exists():
        console.print(f"[red]Error:[/] Manifest not found: {manifest_path}")
        console.print("Run [bold]openworlds manifest generate[/] first.")
        raise typer.Exit(1)

    manifest_data = json.loads(manifest_path.read_text())
    manifest = Manifest.model_validate(manifest_data)

    console.print(Panel.fit(
        f"[bold green]OpenWorlds Interactive Shell v{__version__}[/]\n"
        f"Domain: [bold]{manifest.domain.name}[/] | "
        f"Hosts: {len(manifest.hosts)} | Users: {len(manifest.users)}",
        border_style="green",
    ))
    console.print("Type [bold]help[/] for commands, [bold]exit[/] to quit.\n")

    # Import tool simulator
    try:
        from openworlds.tools.simulator import ToolSimulator
        simulator = ToolSimulator(manifest)
    except ImportError:
        simulator = None
        console.print("[yellow]⚠ Tool simulator not yet available. Shell in read-only mode.[/]\n")

    while True:
        try:
            cmd = console.input("[bold blue]openworlds>[/] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\nGoodbye! 👋")
            break

        if not cmd:
            continue

        if cmd.lower() in {"exit", "quit", "q"}:
            console.print("Goodbye! 👋")
            break
        elif cmd.lower() == "help":
            _shell_help()
        elif cmd.lower() == "hosts":
            _shell_hosts(manifest)
        elif cmd.lower() == "users":
            _shell_users(manifest)
        elif cmd.lower() == "groups":
            _shell_groups(manifest)
        elif cmd.lower() == "paths":
            _shell_paths(manifest)
        elif cmd.lower() == "domain":
            _shell_domain(manifest)
        elif cmd.lower().startswith("host "):
            _shell_host_detail(manifest, cmd.split(" ", 1)[1])
        elif cmd.lower().startswith("user "):
            _shell_user_detail(manifest, cmd.split(" ", 1)[1])
        elif simulator and cmd.lower().startswith("run "):
            result = simulator.execute(cmd[4:].strip())
            console.print(result)
        else:
            console.print(f"[red]Unknown command:[/] {cmd}. Type [bold]help[/].")


# ---------------------------------------------------------------------------
# Version command
# ---------------------------------------------------------------------------


@app.command("version")
def version() -> None:
    """Show the OpenWorlds version."""
    console.print(f"OpenWorlds v{__version__}")


# ---------------------------------------------------------------------------
# Shell helper functions
# ---------------------------------------------------------------------------


def _shell_help() -> None:
    """Display shell help."""
    table = Table(title="Available Commands", show_header=True)
    table.add_column("Command", style="bold cyan")
    table.add_column("Description")
    table.add_row("hosts", "List all hosts in the network")
    table.add_row("host <hostname>", "Show details of a specific host")
    table.add_row("users", "List all users")
    table.add_row("user <SAM>", "Show details of a specific user")
    table.add_row("groups", "List all groups")
    table.add_row("paths", "Show discovered attack paths")
    table.add_row("domain", "Show domain information")
    table.add_row("run <command>", "Execute a simulated tool command")
    table.add_row("help", "Show this help")
    table.add_row("exit", "Exit the shell")
    console.print(table)


def _shell_hosts(manifest: object) -> None:
    """List all hosts."""
    table = Table(title="Hosts", show_header=True)
    table.add_column("Hostname", style="bold")
    table.add_column("IP")
    table.add_column("OS")
    table.add_column("Type")
    table.add_column("Services", justify="right")

    for host in manifest.hosts:  # type: ignore
        table.add_row(
            host.hostname, host.ip, host.os,
            host.host_type.value, str(len(host.services)),
        )
    console.print(table)


def _shell_users(manifest: object) -> None:
    """List users summary."""
    table = Table(title="Users", show_header=True)
    table.add_column("SAMAccountName", style="bold")
    table.add_column("Type")
    table.add_column("SPN")
    table.add_column("AS-REP")
    table.add_column("Admin")
    table.add_column("Groups")

    for user in manifest.users:  # type: ignore
        table.add_row(
            user.sam_account_name,
            user.user_type.value,
            "✓" if user.spn else "",
            "✓" if user.asrep_roastable else "",
            "✓" if user.admin_count else "",
            str(len(user.member_of)),
        )
    console.print(table)


def _shell_groups(manifest: object) -> None:
    """List groups."""
    table = Table(title="Groups", show_header=True)
    table.add_column("Name", style="bold")
    table.add_column("Type")
    table.add_column("Scope")
    table.add_column("Members", justify="right")

    for group in manifest.groups:  # type: ignore
        table.add_row(
            group.name, group.group_type,
            group.group_scope, str(len(group.members)),
        )
    console.print(table)


def _shell_paths(manifest: object) -> None:
    """Display attack paths."""
    paths = manifest.attack_paths  # type: ignore
    if not paths:
        console.print("[yellow]No attack paths found.[/]")
        return

    for idx, path in enumerate(paths):
        tree = Tree(f"[bold red]Attack Path {idx + 1}[/] ({path.total_steps} steps)")
        tree.add(f"Start: [green]{path.starting_user}[/] @ {path.starting_host}")
        tree.add(f"Strategies: [cyan]{', '.join(path.strategies_used)}[/]")

        for step in path.steps:
            step_node = tree.add(
                f"Step {step.step_number}: "
                f"[yellow]{step.technique}[/] → {step.target_principal}"
            )
            step_node.add(f"[dim]{step.description}[/]")

        tree.add(f"[bold red]🎯 Target: {path.target}[/]")
        console.print(tree)
        console.print()


def _shell_domain(manifest: object) -> None:
    """Display domain info."""
    d = manifest.domain  # type: ignore
    panel_text = (
        f"[bold]Domain:[/] {d.name}\n"
        f"[bold]NetBIOS:[/] {d.netbios_name}\n"
        f"[bold]Functional Level:[/] {d.functional_level}\n"
        f"[bold]SID:[/] {d.domain_sid}\n"
        f"[bold]Subnets:[/] {len(d.subnets)}\n"
        f"[bold]Forest Root:[/] {d.forest_root}"
    )
    console.print(Panel(panel_text, title="Domain Information", border_style="blue"))


def _shell_host_detail(manifest: object, hostname: str) -> None:
    """Show host details."""
    host = next(
        (h for h in manifest.hosts if h.hostname.lower() == hostname.lower()),  # type: ignore
        None,
    )
    if not host:
        console.print(f"[red]Host not found:[/] {hostname}")
        return

    info = (
        f"[bold]Hostname:[/] {host.hostname}\n"
        f"[bold]FQDN:[/] {host.fqdn}\n"
        f"[bold]IP:[/] {host.ip}\n"
        f"[bold]OS:[/] {host.os} (Build {host.os_build})\n"
        f"[bold]Type:[/] {host.host_type.value}\n"
        f"[bold]Local Admins:[/] {', '.join(host.local_admins) or 'None'}"
    )
    console.print(Panel(info, title=f"Host: {host.hostname}", border_style="blue"))

    if host.services:
        svc_table = Table(title="Services")
        svc_table.add_column("Port")
        svc_table.add_column("Name")
        svc_table.add_column("Version")
        for svc in host.services:
            svc_table.add_row(str(svc.port), svc.name, svc.version)
        console.print(svc_table)

    if host.shares:
        share_table = Table(title="Shares")
        share_table.add_column("Name")
        share_table.add_column("Files", justify="right")
        share_table.add_column("Sensitive")
        for share in host.shares:
            sensitive = "⚠️" if any(f.sensitive for f in share.files) else ""
            share_table.add_row(share.name, str(len(share.files)), sensitive)
        console.print(share_table)


def _shell_user_detail(manifest: object, sam: str) -> None:
    """Show user details."""
    user = next(
        (u for u in manifest.users if u.sam_account_name.lower() == sam.lower()),  # type: ignore
        None,
    )
    if not user:
        console.print(f"[red]User not found:[/] {sam}")
        return

    info = (
        f"[bold]SAMAccountName:[/] {user.sam_account_name}\n"
        f"[bold]Display Name:[/] {user.display_name}\n"
        f"[bold]UPN:[/] {user.upn}\n"
        f"[bold]Type:[/] {user.user_type.value}\n"
        f"[bold]SID:[/] {user.sid}\n"
        f"[bold]OU:[/] {user.ou}\n"
        f"[bold]Groups:[/] {', '.join(user.member_of)}\n"
        f"[bold]SPN:[/] {user.spn or 'None'}\n"
        f"[bold]AS-REP Roastable:[/] {user.asrep_roastable}\n"
        f"[bold]Password Strength:[/] {user.password_strength.value}\n"
        f"[bold]NT Hash:[/] {user.nt_hash}"
    )
    console.print(Panel(info, title=f"User: {user.sam_account_name}", border_style="green"))


# ---------------------------------------------------------------------------
# Summary display
# ---------------------------------------------------------------------------


def _display_manifest_summary(manifest: object, path: Path) -> None:
    """Display a rich summary of a manifest."""
    m = manifest  # type: ignore

    # Summary panel
    panel_text = (
        f"[bold]Domain:[/] {m.domain.name}\n"
        f"[bold]Hosts:[/] {len(m.hosts)} | [bold]Users:[/] {len(m.users)} | "
        f"[bold]Groups:[/] {len(m.groups)}\n"
        f"[bold]OUs:[/] {len(m.ous)} | [bold]ACLs:[/] {len(m.acls)} | "
        f"[bold]Cert Templates:[/] {len(m.cert_templates)}\n"
        f"[bold]Attack Paths:[/] {len(m.attack_paths)}\n"
        f"[bold]Seed:[/] {m.seed}\n"
        f"[bold]Saved to:[/] {path}"
    )
    console.print(Panel(panel_text, title="🌐 OpenWorlds Manifest", border_style="green"))

    # Host type breakdown
    host_types: dict[str, int] = {}
    for host in m.hosts:
        t = host.host_type.value
        host_types[t] = host_types.get(t, 0) + 1

    table = Table(title="Host Types")
    table.add_column("Type", style="bold")
    table.add_column("Count", justify="right")
    for htype, count in sorted(host_types.items()):
        table.add_row(htype, str(count))
    console.print(table)

    # Vulnerability summary
    vuln_table = Table(title="Vulnerability Summary")
    vuln_table.add_column("Category", style="bold")
    vuln_table.add_column("Count", justify="right")

    spn_users = sum(1 for u in m.users if u.spn)
    asrep_users = sum(1 for u in m.users if u.asrep_roastable)
    vuln_certs = sum(
        1 for c in m.cert_templates if c.enrollee_supplies_subject or c.any_purpose
    )
    sensitive_files = sum(
        1 for h in m.hosts for s in h.shares for f in s.files if f.sensitive
    )

    vuln_table.add_row("Kerberoastable accounts", str(spn_users))
    vuln_table.add_row("AS-REP Roastable accounts", str(asrep_users))
    vuln_table.add_row("ACL abuse entries", str(len(m.acls)))
    vuln_table.add_row("Vulnerable cert templates", str(vuln_certs))
    vuln_table.add_row("Sensitive files in shares", str(sensitive_files))
    console.print(vuln_table)

    # Attack path summary
    if m.attack_paths:
        path_table = Table(title="Attack Paths")
        path_table.add_column("#", justify="right")
        path_table.add_column("Steps", justify="right")
        path_table.add_column("Strategies")
        for idx, path in enumerate(m.attack_paths[:10]):
            path_table.add_row(
                str(idx + 1),
                str(path.total_steps),
                ", ".join(path.strategies_used),
            )
        console.print(path_table)


if __name__ == "__main__":
    app()
