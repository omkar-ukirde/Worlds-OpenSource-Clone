"""Reasoning Engine — generates <think> traces for trajectory steps.

Two modes:
    1. Template-based (default): Rule-based reasoning per attack technique.
       No LLM needed — works offline and produces consistent output.
    2. LLM-augmented (optional): Sends context to Ollama/vLLM for richer
       reasoning. Requires a running inference server.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Template-based reasoning (default — no LLM needed)
# ---------------------------------------------------------------------------

# Maps technique → reasoning template.
# Placeholders: {target}, {source}, {domain}, {dc_ip}, {tool}, {prior_info}
REASONING_TEMPLATES: dict[str, list[str]] = {
    # Initial reconnaissance
    "recon_nmap": [
        (
            "I have initial credentials for {source} in the {domain} domain. "
            "My first step is network reconnaissance — I need to identify live hosts, "
            "the Domain Controller, and available services. An nmap service scan on the "
            "subnet will reveal the network topology and potential attack surfaces."
        ),
        (
            "Before I can plan an attack path, I need to understand the network layout. "
            "I'll run a service version scan to identify the Domain Controller, "
            "any SQL servers, web servers, and workstations. This will tell me "
            "what services are available and help prioritize targets."
        ),
    ],
    "recon_ldap": [
        (
            "Now that I've identified the Domain Controller at {dc_ip}, "
            "I should enumerate Active Directory objects via LDAP. "
            "This will reveal users, groups, service accounts with SPNs, "
            "and potential Kerberoasting targets."
        ),
        (
            "With LDAP access to the DC, I can query for all user objects and group "
            "memberships. I'm specifically looking for service accounts with SPNs "
            "(Kerberoastable) and users without pre-authentication (AS-REP roastable)."
        ),
    ],
    "recon_bloodhound": [
        (
            "I should collect Active Directory relationship data to map out "
            "attack paths. BloodHound will enumerate group memberships, "
            "ACL permissions, and local admin relationships across the domain."
        ),
    ],
    # Kerberoasting
    "kerberoasting": [
        (
            "The LDAP enumeration revealed that {target} has a Service Principal Name "
            "registered. This makes them vulnerable to Kerberoasting — I can request "
            "a TGS ticket encrypted with their password hash and attempt to crack it "
            "offline. I'll use GetUserSPNs to extract the ticket."
        ),
        (
            "I identified {target} as a service account with an SPN. "
            "Kerberoasting allows me to request a service ticket and crack the hash offline "
            "without triggering account lockout. If the password is weak, "
            "I'll obtain their plaintext credentials."
        ),
    ],
    # AS-REP Roasting
    "asrep_roasting": [
        (
            "During enumeration, I found that {target} does not require Kerberos "
            "pre-authentication. This means I can request an AS-REP encrypted "
            "with their password hash and crack it offline. I'll use GetNPUsers "
            "to extract the hash."
        ),
        (
            "The user {target} has pre-authentication disabled (UF_DONT_REQUIRE_PREAUTH). "
            "I can perform AS-REP Roasting to obtain their encrypted TGT and attempt "
            "an offline crack without needing any prior credentials."
        ),
    ],
    # Hash cracking
    "hash_crack": [
        (
            "I've obtained a Kerberos hash for {target}. I'll run hashcat "
            "with a wordlist to try to crack it. If the service account "
            "uses a weak or common password, this should succeed quickly."
        ),
        (
            "Time to crack the hash I extracted for {target}. Using hashcat "
            "with mode {hashcat_mode} against a common password wordlist. "
            "Service accounts often have weaker passwords than regular users."
        ),
    ],
    # ACL abuse
    "acl_abuse": [
        (
            "With {source}'s credentials, I can exploit their ACL permissions. "
            "{source} has {acl_right} rights over {target}, which allows me to "
            "modify their attributes or reset their password. This is a classic "
            "AD privilege escalation via misconfigured ACLs."
        ),
        (
            "The ACL audit revealed that {source} holds {acl_right} on {target}. "
            "This excessive permission allows me to escalate privileges — "
            "I can abuse this to gain control over {target}'s account."
        ),
    ],
    # DCSync
    "dcsync": [
        (
            "Now that I have an account with DS-Replication-Get-Changes-All rights, "
            "I can perform a DCSync attack to replicate all domain password hashes "
            "from the Domain Controller. This effectively gives me every credential "
            "in the domain, including the krbtgt and Administrator accounts."
        ),
        (
            "With DCSync privileges via {source}, I can replicate the Active Directory "
            "database. This will dump all NTLM hashes for every domain user, "
            "achieving full domain compromise without touching the DC's disk."
        ),
    ],
    # AD CS exploitation
    "adcs_esc1": [
        (
            "I found a vulnerable certificate template that allows the enrollee to supply "
            "the Subject Alternative Name (SAN). This is ESC1 — I can request a certificate "
            "as {target} (a Domain Admin) and use it to authenticate, effectively "
            "impersonating them without knowing their password."
        ),
        (
            "The certificate template allows me to specify any UPN in the SAN field. "
            "I'll request a certificate impersonating {target} and use it for "
            "PKINIT authentication to obtain their TGT."
        ),
    ],
    # Share credential discovery
    "share_credential": [
        (
            "During share enumeration, I found a file containing credentials. "
            "Administrators often leave passwords in scripts, configuration files, "
            "or Group Policy Preference XML files. I'll retrieve the file and "
            "extract the credentials for {target}."
        ),
        (
            "I noticed a sensitive file on an SMB share that may contain hardcoded "
            "credentials. This is a common finding — passwords in batch scripts, "
            "PowerShell profiles, or GPP XML files on SYSVOL. Let me retrieve it."
        ),
    ],
    # Credential pivot
    "credential_pivot": [
        (
            "I now have valid credentials for {target}. I can use these to "
            "authenticate against other services and hosts in the domain. "
            "Let me check what access this account has with CrackMapExec."
        ),
    ],
    # Group membership escalation
    "group_membership": [
        (
            "{source} is a member of a privileged group that grants access to "
            "{target}. This group membership provides escalated privileges "
            "that I can leverage for further lateral movement."
        ),
    ],
    # Final verification
    "verification_winrm": [
        (
            "I've obtained Domain Admin credentials. Let me verify by connecting "
            "to the Domain Controller via WinRM to confirm I have full "
            "administrative access and can execute commands."
        ),
    ],
    "verification_dcsync": [
        (
            "To confirm Domain Admin access, I'll perform a DCSync to dump "
            "the krbtgt hash. If successful, this proves full domain compromise "
            "— I could forge Golden Tickets for persistent access."
        ),
    ],
}


def generate_reasoning(
    technique: str,
    source: str = "",
    target: str = "",
    domain: str = "",
    dc_ip: str = "",
    acl_right: str = "",
    prior_info: str = "",
    step_index: int = 0,
    **kwargs: Any,
) -> str:
    """Generate a <think> reasoning trace for a trajectory step.

    Uses template-based reasoning. Selects from available templates
    based on the technique and step_index for variety.

    Args:
        technique: Attack technique name (e.g. 'kerberoasting', 'recon_nmap')
        source: The user performing the action
        target: The target principal
        domain: Domain name
        dc_ip: DC IP address
        acl_right: ACL right being abused (for acl_abuse)
        prior_info: Summary of prior observations
        step_index: Index for template variety

    Returns:
        Reasoning text (without <think> tags — caller wraps them).
    """
    templates = REASONING_TEMPLATES.get(technique, [])
    if not templates:
        # Fallback for unknown techniques
        return (
            f"Based on my enumeration so far, the next logical step is to "
            f"target {target} using the {technique} technique. "
            f"This should advance my position toward Domain Admin."
        )

    # Select template based on step index for variety
    template = templates[step_index % len(templates)]

    # Format with available context
    hashcat_mode = "13100" if "kerberoast" in technique else "18200"
    try:
        return template.format(
            source=source or "current user",
            target=target or "target",
            domain=domain or "the domain",
            dc_ip=dc_ip or "DC",
            acl_right=acl_right or "excessive permissions",
            prior_info=prior_info or "",
            tool="tool",
            hashcat_mode=hashcat_mode,
        )
    except KeyError:
        return template  # Return raw template if formatting fails


def generate_reasoning_llm(
    technique: str,
    trajectory_context: str,
    next_action: str,
    next_observation: str,
    api_base: str = "http://localhost:11434/v1",
    model: str = "qwen2.5:32b",
) -> str:
    """Generate reasoning via an LLM (Ollama/vLLM).

    Requires a running OpenAI-compatible inference server.
    Falls back to template-based reasoning on failure.

    Args:
        technique: Attack technique name
        trajectory_context: Full trajectory so far
        next_action: The tool command that was executed
        next_observation: The tool output
        api_base: OpenAI-compatible API base URL
        model: Model name

    Returns:
        LLM-generated reasoning text.
    """
    try:
        from openai import OpenAI

        client = OpenAI(
            base_url=api_base, api_key="unused", timeout=10.0,
        )

        prompt = (
            "You are an expert penetration tester narrating your thought process "
            "during an Active Directory pentest.\n\n"
            f"TRAJECTORY SO FAR:\n{trajectory_context}\n\n"
            f"NEXT COMMAND EXECUTED:\n{next_action}\n\n"
            f"RESULT:\n{next_observation[:500]}\n\n"
            "Generate the reasoning (3-5 sentences) that an expert would have "
            "BEFORE executing the above command. The reasoning MUST:\n"
            "1. Reference specific information from previous steps\n"
            "2. Explain WHY this is the logical next step\n"
            "3. State what you expect to find\n\n"
            "Output ONLY the reasoning text, no tags or formatting."
        )

        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200,
            temperature=0.7,
        )

        result = response.choices[0].message.content
        if result and len(result.strip()) > 20:
            return result.strip()

    except Exception:
        pass

    # Fallback to template
    return generate_reasoning(technique)
