"""Failure Injector — injects realistic mistakes into trajectories.

Inserts failed attempts before random successful steps, teaching the
model to recover from errors.  Each failure consists of:
    1. A broken command (the mistake)
    2. An error output
    3. The original correct command follows naturally

Failure types:
    - Typos in tool names
    - Wrong credentials
    - Wrong target IPs (non-existent hosts)
    - Malformed arguments
    - Wrong tool choice
"""

from __future__ import annotations

import copy
import random

from openworlds.trajectory.generator import Trajectory, TrajectoryStep


# ---------------------------------------------------------------------------
# Failure templates
# ---------------------------------------------------------------------------

TYPO_VARIANTS: dict[str, list[str]] = {
    "nmap": ["namp", "nmpa", "nma"],
    "ldapsearch": ["ldapserach", "ldpasearch", "ladpsearch"],
    "smbclient": ["smbclinet", "smbclien", "smbcleint"],
    "crackmapexec": ["crakmapexec", "crackmpexec"],
    "hashcat": ["haschat", "hashact", "hahscat"],
    "certipy": ["certpy", "ceritpy", "certipy"],
    "evil-winrm": ["evil-wirm", "evil-winm", "evli-winrm"],
}

WRONG_TOOL_SUGGESTIONS: list[tuple[str, str]] = [
    ("msfconsole", "bash: msfconsole: command not found"),
    ("responder", "bash: responder: command not found"),
    ("mimikatz", "bash: mimikatz: command not found"),
    ("powershell", "bash: powershell: command not found"),
    ("net user /domain", "bash: net: command not found"),
]


class FailureInjector:
    """Injects realistic failures into trajectories.

    Usage:
        injector = FailureInjector(failure_rate=0.15, seed=42)
        augmented = injector.inject(trajectory)
    """

    def __init__(
        self,
        failure_rate: float = 0.15,
        seed: int | None = None,
    ) -> None:
        """Initialize the failure injector.

        Args:
            failure_rate: Probability of injecting a failure before each step.
                          Default: 0.15 (15% of steps get a failure prepended).
            seed: Random seed for reproducibility.
        """
        self.failure_rate = failure_rate
        self.rng = random.Random(seed)

    def inject(self, trajectory: Trajectory) -> Trajectory:
        """Inject failures into a trajectory.

        Returns a new Trajectory with failure steps inserted.
        Does NOT modify the original trajectory.
        """
        result = trajectory.model_copy(deep=True)
        augmented_steps: list[TrajectoryStep] = []
        step_num = 1

        for step in result.steps:
            # Skip first step (recon) and verification — only inject in middle
            is_skippable = (
                step.technique.startswith("recon_")
                or step.technique == "verification"
            )

            if not is_skippable and self.rng.random() < self.failure_rate:
                failure_step = self._generate_failure(step, step_num)
                if failure_step:
                    augmented_steps.append(failure_step)
                    step_num += 1

            # Add the original step with updated number
            step.step_number = step_num
            augmented_steps.append(step)
            step_num += 1

        result.steps = augmented_steps
        result.total_steps = len(augmented_steps)
        return result

    def _generate_failure(
        self, original_step: TrajectoryStep, step_num: int,
    ) -> TrajectoryStep | None:
        """Generate a failure step based on the original command."""
        failure_type = self.rng.choice([
            "typo", "wrong_creds", "wrong_target", "malformed_args", "wrong_tool",
        ])

        if failure_type == "typo":
            return self._typo_failure(original_step, step_num)
        elif failure_type == "wrong_creds":
            return self._wrong_creds_failure(original_step, step_num)
        elif failure_type == "wrong_target":
            return self._wrong_target_failure(original_step, step_num)
        elif failure_type == "malformed_args":
            return self._malformed_args_failure(original_step, step_num)
        elif failure_type == "wrong_tool":
            return self._wrong_tool_failure(original_step, step_num)
        return None

    def _typo_failure(
        self, original: TrajectoryStep, step_num: int,
    ) -> TrajectoryStep | None:
        """Inject a typo in the tool name."""
        parts = original.action.split()
        if not parts:
            return None

        tool_name = parts[0]
        # Find typo variants for this tool
        for real_tool, typos in TYPO_VARIANTS.items():
            if real_tool in tool_name.lower():
                typo = self.rng.choice(typos)
                broken_cmd = original.action.replace(parts[0], typo, 1)
                return TrajectoryStep(
                    step_number=step_num,
                    action=broken_cmd,
                    observation=f"bash: {typo}: command not found",
                    reasoning=(
                        f"I need to run {parts[0]} but made a typo. "
                        f"Let me correct the command."
                    ),
                    technique=original.technique,
                    is_failure=True,
                )
        return None

    def _wrong_creds_failure(
        self, original: TrajectoryStep, step_num: int,
    ) -> TrajectoryStep | None:
        """Use wrong credentials."""
        if ":" not in original.action:
            return None

        # Replace password with a wrong one
        wrong_passwords = ["Password1", "admin", "Welcome1!", "changeme", "P@ssw0rd"]
        wrong_pass = self.rng.choice(wrong_passwords)

        # Find DOMAIN/user:password pattern
        parts = original.action.split()
        broken_parts = []
        for part in parts:
            if "/" in part and ":" in part:
                domain_user, _ = part.rsplit(":", 1)
                at_suffix = ""
                if "@" in _:
                    _, at_suffix = _.split("@", 1)
                    at_suffix = "@" + at_suffix
                broken_parts.append(f"{domain_user}:{wrong_pass}{at_suffix}")
            else:
                broken_parts.append(part)

        broken_cmd = " ".join(broken_parts)
        if broken_cmd == original.action:
            return None

        return TrajectoryStep(
            step_number=step_num,
            action=broken_cmd,
            observation=(
                "[-] ERROR: STATUS_LOGON_FAILURE "
                "(The attempted logon is invalid. Either the username or "
                "the authentication information is incorrect.)"
            ),
            reasoning=(
                "The credentials were rejected. I must have used the wrong "
                "password. Let me try with the correct credentials I obtained."
            ),
            technique=original.technique,
            is_failure=True,
        )

    def _wrong_target_failure(
        self, original: TrajectoryStep, step_num: int,
    ) -> TrajectoryStep | None:
        """Target a non-existent IP address."""
        # Find an IP in the command and change the last octet
        parts = original.action.split()
        broken_parts = []
        replaced = False

        for part in parts:
            if not replaced and self._looks_like_ip(part):
                octets = part.split(".")
                if len(octets) == 4:
                    octets[3] = str(self.rng.randint(200, 254))
                    broken_parts.append(".".join(octets))
                    replaced = True
                    continue
            broken_parts.append(part)

        if not replaced:
            return None

        broken_cmd = " ".join(broken_parts)
        return TrajectoryStep(
            step_number=step_num,
            action=broken_cmd,
            observation=(
                "Connection timed out. Host seems down or unreachable.\n"
                "Note: Host seems down. If it is really up, but blocking "
                "our ping probes, try -Pn"
            ),
            reasoning=(
                "The target host is not responding. I may have the wrong IP. "
                "Let me double-check the IP from my earlier scan results."
            ),
            technique=original.technique,
            is_failure=True,
        )

    def _malformed_args_failure(
        self, original: TrajectoryStep, step_num: int,
    ) -> TrajectoryStep | None:
        """Remove a required argument or flag."""
        parts = original.action.split()
        if len(parts) < 3:
            return None

        # Remove a random flag (not the first or last element)
        removable = [
            i for i, p in enumerate(parts[1:-1], 1)
            if p.startswith("-")
        ]
        if not removable:
            return None

        idx = self.rng.choice(removable)
        broken_parts = parts[:idx] + parts[idx + 1:]
        broken_cmd = " ".join(broken_parts)

        return TrajectoryStep(
            step_number=step_num,
            action=broken_cmd,
            observation="Error: Missing required argument. See --help for usage.",
            reasoning=(
                "I forgot a required flag. Let me check the correct syntax "
                "and run the command again with all necessary arguments."
            ),
            technique=original.technique,
            is_failure=True,
        )

    def _wrong_tool_failure(
        self, original: TrajectoryStep, step_num: int,
    ) -> TrajectoryStep:
        """Try a tool that isn't available."""
        wrong_tool, error_msg = self.rng.choice(WRONG_TOOL_SUGGESTIONS)
        return TrajectoryStep(
            step_number=step_num,
            action=wrong_tool,
            observation=error_msg,
            reasoning=(
                f"'{wrong_tool}' is not available in this environment. "
                f"I should use the equivalent tool from the available toolkit."
            ),
            technique=original.technique,
            is_failure=True,
        )

    @staticmethod
    def _looks_like_ip(text: str) -> bool:
        """Check if text looks like an IP address."""
        parts = text.split(".")
        if len(parts) != 4:
            return False
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
