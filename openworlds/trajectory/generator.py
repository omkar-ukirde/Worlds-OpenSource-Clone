"""Trajectory Generator — walks attack paths to produce training data.

Takes a Manifest with validated attack paths and produces Trajectory
objects by:
    1. Picking a starting point (user, host)
    2. Adding reconnaissance steps (nmap, ldapsearch)
    3. Walking each AttackStep through the ToolSimulator
    4. Adding hash cracking steps after hash-based attacks
    5. Adding a final DA verification step
    6. Attaching <think> reasoning to each step
"""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from openworlds.tools.simulator import ToolSimulator
from openworlds.trajectory.reasoning import generate_reasoning
from openworlds.trajectory.state_tracker import (
    CredentialType,
    StateTracker,
)
from openworlds.world_engine.models import (
    AttackPath,
    HostType,
    Manifest,
    PasswordStrength,
)


# ---------------------------------------------------------------------------
# Trajectory data models
# ---------------------------------------------------------------------------


class TrajectoryStep(BaseModel):
    """A single step in a trajectory (action + observation + reasoning)."""

    step_number: int
    action: str = Field(description="The tool command the agent typed")
    observation: str = Field(description="The simulated tool output")
    reasoning: str = Field(default="", description="<think> reasoning trace")
    technique: str = Field(default="", description="Attack technique used")
    is_failure: bool = Field(default=False, description="Is this a failed attempt?")


class Trajectory(BaseModel):
    """A complete pentest trajectory from initial access to DA."""

    trajectory_id: str
    manifest_seed: int | None = None
    domain: str
    starting_user: str
    starting_host: str
    starting_ip: str
    objective: str = "Achieve Domain Admin"
    steps: list[TrajectoryStep] = Field(default_factory=list)
    success: bool = False
    total_steps: int = 0
    strategies_used: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


class TrajectoryGenerator:
    """Generates training trajectories by walking attack paths.

    Usage:
        gen = TrajectoryGenerator(manifest)
        trajectory = gen.generate_one(path_index=0)
        trajectories = gen.generate_all()
    """

    def __init__(
        self,
        manifest: Manifest,
        seed: int | None = None,
    ) -> None:
        self.manifest = manifest
        self.simulator = ToolSimulator(manifest)
        self.rng = random.Random(seed)

    def generate_one(
        self,
        path_index: int = 0,
        include_recon: bool = True,
    ) -> Trajectory:
        """Generate a single trajectory from an attack path.

        Args:
            path_index: Index of the attack path to walk.
            include_recon: Whether to add recon steps (nmap, ldapsearch).

        Returns:
            A complete Trajectory object.
        """
        if not self.manifest.attack_paths:
            raise ValueError("Manifest has no attack paths. Run PathValidator first.")

        path = self.manifest.attack_paths[path_index % len(self.manifest.attack_paths)]
        return self._walk_path(path, include_recon=include_recon)

    def generate_all(
        self,
        max_trajectories: int | None = None,
        include_recon: bool = True,
    ) -> list[Trajectory]:
        """Generate trajectories from all attack paths.

        Args:
            max_trajectories: Limit the number of trajectories.
            include_recon: Whether to add recon steps.

        Returns:
            List of Trajectory objects.
        """
        paths = self.manifest.attack_paths
        if max_trajectories:
            paths = paths[:max_trajectories]

        return [
            self._walk_path(path, include_recon=include_recon)
            for path in paths
        ]

    # ------------------------------------------------------------------
    # Internal: walk an attack path
    # ------------------------------------------------------------------

    def _walk_path(
        self,
        path: AttackPath,
        include_recon: bool = True,
    ) -> Trajectory:
        """Walk a single attack path, producing a trajectory."""
        # Find starting user and host
        start_user = self._find_user(path.starting_user)
        start_host = self._find_host(path.starting_host)

        if not start_user or not start_host:
            raise ValueError(
                f"Starting user '{path.starting_user}' or host "
                f"'{path.starting_host}' not found in manifest."
            )

        # Initialize state tracker
        state = StateTracker(
            domain=self.manifest.domain.name,
            start_user=start_user.sam_account_name,
            start_pass=start_user.password,
            start_host=start_host.hostname,
            start_ip=start_host.ip,
        )

        dc = self._get_dc()
        dc_ip = dc.ip if dc else "10.0.1.1"

        trajectory = Trajectory(
            trajectory_id=str(uuid.uuid4())[:8],
            manifest_seed=self.manifest.seed,
            domain=self.manifest.domain.name,
            starting_user=start_user.sam_account_name,
            starting_host=start_host.hostname,
            starting_ip=start_host.ip,
            strategies_used=path.strategies_used,
        )

        step_num = 1

        # --- Phase 1: Reconnaissance ---
        if include_recon:
            step_num = self._add_recon_steps(
                trajectory, state, start_user, dc_ip, step_num,
            )

        # --- Phase 2: Walk attack steps ---
        for i, attack_step in enumerate(path.steps):
            step_num = self._add_attack_step(
                trajectory, state, attack_step, dc_ip, step_num, i,
            )

        # --- Phase 3: Verification ---
        step_num = self._add_verification_step(
            trajectory, state, dc_ip, step_num,
        )

        trajectory.success = True
        trajectory.total_steps = len(trajectory.steps)
        return trajectory

    # ------------------------------------------------------------------
    # Recon phase
    # ------------------------------------------------------------------

    def _add_recon_steps(
        self,
        trajectory: Trajectory,
        state: StateTracker,
        start_user: Any,
        dc_ip: str,
        step_num: int,
    ) -> int:
        """Add reconnaissance steps (nmap + ldapsearch)."""
        domain = self.manifest.domain.name

        # Step: nmap scan of DC
        nmap_cmd = f"nmap -sV -sC {dc_ip}"
        nmap_output = self.simulator.execute(nmap_cmd)
        reasoning = generate_reasoning(
            "recon_nmap",
            source=start_user.sam_account_name,
            domain=domain,
            dc_ip=dc_ip,
        )

        trajectory.steps.append(TrajectoryStep(
            step_number=step_num,
            action=nmap_cmd,
            observation=nmap_output,
            reasoning=reasoning,
            technique="recon_nmap",
        ))
        step_num += 1

        # Step: LDAP enumeration for users with SPNs
        dc_components = ",".join(f"DC={p}" for p in domain.split("."))
        ldap_cmd = (
            f"ldapsearch -x -H ldap://{dc_ip} -D "
            f"\"{self.manifest.domain.netbios_name}\\\\{start_user.sam_account_name}\" "
            f"-w {start_user.password} -b \"{dc_components}\" "
            f"\"(servicePrincipalName=*)\" sAMAccountName servicePrincipalName"
        )
        ldap_output = self.simulator.execute(
            f"ldapsearch -x -H ldap://{dc_ip} -b {dc_components} "
            f"'(servicePrincipalName=*)'"
        )
        reasoning = generate_reasoning(
            "recon_ldap",
            source=start_user.sam_account_name,
            domain=domain,
            dc_ip=dc_ip,
            step_index=0,
        )

        trajectory.steps.append(TrajectoryStep(
            step_number=step_num,
            action=ldap_cmd,
            observation=ldap_output,
            reasoning=reasoning,
            technique="recon_ldap",
        ))
        step_num += 1

        return step_num

    # ------------------------------------------------------------------
    # Attack steps
    # ------------------------------------------------------------------

    def _add_attack_step(
        self,
        trajectory: Trajectory,
        state: StateTracker,
        attack_step: Any,
        dc_ip: str,
        step_num: int,
        step_index: int,
    ) -> int:
        """Add an attack step from the attack path."""
        technique = attack_step.technique
        source = attack_step.source_principal
        target = attack_step.target_principal
        domain = self.manifest.domain.name

        # Generate the tool command
        cmd = attack_step.tool_command
        output = self.simulator.execute(cmd)

        # Generate reasoning
        acl_right = ""
        if technique == "acl_abuse":
            # Find the ACL entry
            for acl in self.manifest.acls:
                if acl.source == source and acl.target == target:
                    acl_right = acl.right.value
                    break

        reasoning = generate_reasoning(
            technique,
            source=source,
            target=target,
            domain=domain,
            dc_ip=dc_ip,
            acl_right=acl_right,
            step_index=step_index,
        )

        trajectory.steps.append(TrajectoryStep(
            step_number=step_num,
            action=cmd,
            observation=output,
            reasoning=reasoning,
            technique=technique,
        ))
        step_num += 1

        # Add hash cracking step after Kerberoasting or AS-REP roasting
        if technique in ("kerberoasting", "asrep_roasting"):
            step_num = self._add_hashcrack_step(
                trajectory, state, target, technique, step_num,
            )

        # Update state
        self._update_state(state, technique, source, target)

        return step_num

    def _add_hashcrack_step(
        self,
        trajectory: Trajectory,
        state: StateTracker,
        target: str,
        technique: str,
        step_num: int,
    ) -> int:
        """Add a hashcat step after obtaining a hash."""
        target_user = self._find_user(target)
        if not target_user:
            return step_num

        # Determine hashcat mode
        if technique == "kerberoasting":
            mode = "13100"
            mode_name = "Kerberos 5 TGS-REP"
            hash_prefix = "$krb5tgs$"
        else:
            mode = "18200"
            mode_name = "Kerberos 5 AS-REP"
            hash_prefix = "$krb5asrep$"

        # Determine if crack succeeds
        crack_success = target_user.password_strength in (
            PasswordStrength.WEAK, PasswordStrength.MEDIUM,
        )

        hashcat_cmd = f"hashcat -m {mode} hash.txt /usr/share/wordlists/rockyou.txt --force"

        if crack_success:
            hashcat_output = (
                f"hashcat (v6.2.6) starting...\n\n"
                f"Session..........: hashcat\n"
                f"Status...........: Cracked\n"
                f"Hash.Mode........: {mode} ({mode_name})\n"
                f"Hash.Target......: {hash_prefix}23$*{target}$...\n"
                f"Speed.#1.........:  2140.8 kH/s (8.42ms) @ Accel:256 Loops:1 Thr:64\n"
                f"Recovered........: 1/1 (100.00%) Digests\n"
                f"Progress.........: 14344384/14344384 (100.00%)\n\n"
                f"{hash_prefix}23$*{target}$...:{target_user.password}\n\n"
                f"Session..........: hashcat\n"
                f"Status...........: Cracked\n"
            )
            state.crack_hash(target, target_user.password)
            state.add_credential(
                target, password=target_user.password,
                method=CredentialType.HASH_CRACK,
            )
        else:
            hashcat_output = (
                f"hashcat (v6.2.6) starting...\n\n"
                f"Session..........: hashcat\n"
                f"Status...........: Exhausted\n"
                f"Hash.Mode........: {mode} ({mode_name})\n"
                f"Hash.Target......: {hash_prefix}23$*{target}$...\n"
                f"Speed.#1.........:  2140.8 kH/s (8.42ms) @ Accel:256 Loops:1 Thr:64\n"
                f"Recovered........: 0/1 (0.00%) Digests\n"
                f"Progress.........: 14344384/14344384 (100.00%)\n\n"
                f"Approaching final keyspace - workload adjusted.\n\n"
                f"Session..........: hashcat\n"
                f"Status...........: Exhausted\n"
            )

        reasoning = generate_reasoning(
            "hash_crack",
            target=target,
            step_index=step_num,
        )

        trajectory.steps.append(TrajectoryStep(
            step_number=step_num,
            action=hashcat_cmd,
            observation=hashcat_output,
            reasoning=reasoning,
            technique="hash_crack",
        ))

        return step_num + 1

    # ------------------------------------------------------------------
    # Verification phase
    # ------------------------------------------------------------------

    def _add_verification_step(
        self,
        trajectory: Trajectory,
        state: StateTracker,
        dc_ip: str,
        step_num: int,
    ) -> int:
        """Add a final DA verification step."""
        domain = self.manifest.domain.name

        # Find an admin credential we've obtained
        admin_user = None
        admin_pass = None
        for username, cred in state.credentials.items():
            user_obj = self._find_user(username)
            if user_obj and user_obj.user_type.value == "admin" and cred.has_plaintext:
                admin_user = username
                admin_pass = cred.password
                break

        if not admin_user:
            # Fall back to the last step's target if we have DCSync
            admin_user = state.current_user
            admin_pass = state.credentials.get(admin_user, None)
            if admin_pass:
                admin_pass = admin_pass.password

        if admin_user and admin_pass:
            # Verify via secretsdump DCSync
            cmd = (
                f"impacket-secretsdump {domain}/{admin_user}:{admin_pass}"
                f"@{dc_ip} -just-dc-ntlm"
            )
            output = self.simulator.execute(
                f"secretsdump {domain}/{admin_user}:{admin_pass}@{dc_ip} -just-dc"
            )
            reasoning = generate_reasoning(
                "verification_dcsync",
                source=admin_user,
                domain=domain,
                dc_ip=dc_ip,
            )
        else:
            # Generic verification with CrackMapExec
            user = state.current_user
            cred = state.credentials.get(user)
            password = cred.password if cred else ""
            cmd = f"crackmapexec smb {dc_ip} -u {user} -p {password}"
            output = self.simulator.execute(f"cme smb {dc_ip} -u {user} -p {password}")
            reasoning = generate_reasoning(
                "verification_winrm",
                source=user,
                domain=domain,
            )

        trajectory.steps.append(TrajectoryStep(
            step_number=step_num,
            action=cmd,
            observation=output,
            reasoning=reasoning,
            technique="verification",
        ))

        return step_num + 1

    # ------------------------------------------------------------------
    # State updates
    # ------------------------------------------------------------------

    def _update_state(
        self,
        state: StateTracker,
        technique: str,
        source: str,
        target: str,
    ) -> None:
        """Update state tracker based on what happened."""
        target_user = self._find_user(target)

        if technique == "kerberoasting" and target_user:
            state.add_credential(
                target, nt_hash=target_user.nt_hash,
                method=CredentialType.KERBEROAST,
            )
        elif technique == "asrep_roasting" and target_user:
            state.add_credential(
                target, nt_hash=target_user.nt_hash,
                method=CredentialType.ASREP_ROAST,
            )
        elif technique == "share_credential" and target_user:
            state.add_credential(
                target, password=target_user.password,
                method=CredentialType.SHARE_CREDENTIAL,
            )
        elif technique == "acl_abuse" and target_user:
            state.add_credential(
                target, password=target_user.password,
                method=CredentialType.ACL_ABUSE,
            )
        elif technique == "dcsync":
            # DCSync dumps all hashes
            for u in self.manifest.users:
                state.add_credential(
                    u.sam_account_name, nt_hash=u.nt_hash,
                    method=CredentialType.DCSYNC,
                )
        elif technique == "adcs_esc1" and target_user:
            state.add_credential(
                target, password=target_user.password,
                method=CredentialType.ADCS_ESC1,
            )
        elif technique == "credential_pivot" and target_user:
            state.add_credential(
                target, password=target_user.password,
                method=CredentialType.SHARE_CREDENTIAL,
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _find_user(self, sam: str) -> Any:
        """Find user in manifest."""
        return next(
            (u for u in self.manifest.users
             if u.sam_account_name.lower() == sam.lower()),
            None,
        )

    def _find_host(self, hostname: str) -> Any:
        """Find host in manifest."""
        return next(
            (h for h in self.manifest.hosts
             if h.hostname.lower() == hostname.lower()),
            None,
        )

    def _get_dc(self) -> Any:
        """Get first domain controller."""
        return next(
            (h for h in self.manifest.hosts
             if h.host_type == HostType.DOMAIN_CONTROLLER),
            None,
        )
