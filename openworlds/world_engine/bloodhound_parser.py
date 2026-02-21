"""BloodHound import parser — integrates real AD graphs into OpenWorlds."""

import json
import zipfile
from pathlib import Path

from openworlds.world_engine.models import (
    ACLEntry,
    ACLRight,
    Domain,
    Group,
    Host,
    HostType,
    Manifest,
    ManifestConfig,
    User,
    UserType,
    PasswordStrength,
)


class BloodHoundParser:
    """Parses BloodHound .zip exports into an OpenWorlds Manifest."""

    def __init__(self, zip_path: Path):
        self.zip_path = zip_path
        self.users_data: list[dict] = []
        self.computers_data: list[dict] = []
        self.groups_data: list[dict] = []
        self.domains_data: list[dict] = []

    def parse(self) -> Manifest:
        """Parse the zip and map to OpenWorlds structural objects."""
        self._load_zip()

        # Build Domain
        domain = self._parse_domains()

        # We'll use maps by SID/ObjectIdentifier for cross-referencing
        # BH v4 uses "ObjectIdentifier"
        users_by_sid: dict[str, User] = {}
        hosts_by_sid: dict[str, Host] = {}
        groups_by_sid: dict[str, Group] = {}

        # Parse entities
        manifest = Manifest(
            domain=domain,
            hosts=[],
            users=[],
            groups=[],
            ous=[],
            acls=[],
            seed=42,
            config=ManifestConfig(num_hosts=5, num_users=10, seed=42)
        )

        # 1. Parse Groups
        for gdata in self.groups_data:
            props = gdata.get("Properties", {})
            name = props.get("name", "UnknownGroup").split("@")[0]
            sid = gdata.get("ObjectIdentifier", "")
            sam = props.get("samaccountname", name)
            group = Group(
                name=name,
                sam_account_name=sam,
                dn=f"CN={name},CN=Users,DC={domain.name.replace('.', ',DC=')}",
                sid=sid,
                group_type="security",
                group_scope="global",
                members=[],
                member_of=[],
            )
            groups_by_sid[sid] = group
            manifest.groups.append(group)

        # 2. Parse Users
        for udata in self.users_data:
            props = udata.get("Properties", {})
            name = props.get("name", "UnknownUser").split("@")[0]
            sam = props.get("samaccountname", name)
            sid = udata.get("ObjectIdentifier", "")
            
            # Guesses based on props
            is_admin = props.get("admincount", False)
            user_type = UserType.SERVICE if "svc" in name.lower() else UserType.STANDARD
            if is_admin:
                user_type = UserType.ADMIN
            
            user = User(
                sam_account_name=sam,
                display_name=props.get("displayname", name),
                upn=f"{sam}@{domain.name}",
                dn=f"CN={name},OU=Users,DC={domain.name.replace('.', ',DC=')}",
                user_type=user_type,
                password="Password1",
                password_strength=PasswordStrength.WEAK,
                nt_hash=User.compute_nt_hash("Password1"),
                sid=sid,
                member_of=[],
                ou="Users",
                spn=udata.get("SPNTargets", [])[0].get("ServicePrincipalName", "") if udata.get("SPNTargets") else None,
                asrep_roastable=props.get("dontreqpreauth", False),
                description=props.get("description", ""),
            )
            users_by_sid[sid] = user
            manifest.users.append(user)

        # 3. Parse Computers (Hosts)
        for cdata in self.computers_data:
            props = cdata.get("Properties", {})
            name = props.get("name", "UnknownHost").split(".")[0]
            fqdn = props.get("name", "UnknownHost")
            sid = cdata.get("ObjectIdentifier", "")
            os_str = props.get("operatingsystem", "").lower()
            
            host_type = HostType.WORKSTATION
            if "server" in os_str:
                if "domain controller" in props.get("description", "").lower() or props.get("domain", "") == name:
                    host_type = HostType.DOMAIN_CONTROLLER
                else:
                    host_type = HostType.FILE_SERVER  # Defaulting

            host = Host(
                hostname=name,
                fqdn=fqdn,
                ip="10.0.1.10", # will be overwritten
                mac="00:50:56:00:00:00",
                os=props.get("operatingsystem", "Unknown"),
                os_build="Unknown",
                host_type=host_type,
                subnet="10.0.1.0/24",
                services=[],
                local_admins=[],
                cves=[],
                shares=[],
                installed_software=[]
            )
            hosts_by_sid[sid] = host
            manifest.hosts.append(host)

        # 4. Resolve Group Memberships
        for gdata in self.groups_data:
            sid = gdata.get("ObjectIdentifier", "")
            group = groups_by_sid.get(sid)
            if not group:
                continue

            for member in gdata.get("Members", []):
                mem_sid = member.get("ObjectIdentifier")
                mem_type = member.get("ObjectType")
                if mem_type == "User" and mem_sid in users_by_sid:
                    users_by_sid[mem_sid].member_of.append(group.name)
                elif mem_type == "Group" and mem_sid in groups_by_sid:
                    # Not supporting nested groups in OpenWorlds yet perfectly, just skip or add directly
                    pass
                elif mem_type == "Computer" and mem_sid in hosts_by_sid:
                    # In AD, computer accounts can be in groups
                    pass

        # 5. Extract Inbound ACLs from domains, computers, and groups
        # BH stores inbound rights as "Aces"
        def process_aces(target_name: str, target_type: str, aces: list[dict]):
            for ace in aces:
                principal_sid = ace.get("PrincipalSID")
                right = ace.get("RightName", "")
                
                # Map right to OpenWorlds ACLRight
                mapped_right = None
                if right in ["GenericAll", "AllExtendedRights", "WriteDacl", "WriteOwner", "ForceChangePassword"]:
                    if right in ["GenericAll", "AllExtendedRights"]:
                        mapped_right = ACLRight.GENERIC_ALL
                    elif right == "WriteDacl":
                        mapped_right = ACLRight.WRITE_DACL
                    elif right == "WriteOwner":
                        mapped_right = ACLRight.WRITE_OWNER
                    elif right == "ForceChangePassword":
                        mapped_right = ACLRight.FORCE_CHANGE_PASSWORD
                        
                if mapped_right and principal_sid:
                    # Figure out who the principal name is
                    principal_name = None
                    if principal_sid in users_by_sid:
                        principal_name = users_by_sid[principal_sid].sam_account_name
                    elif principal_sid in groups_by_sid:
                        principal_name = groups_by_sid[principal_sid].name

                    if principal_name:
                        manifest.acls.append(
                            ACLEntry(
                                source=principal_name,
                                target=target_name,
                                right=mapped_right,
                            )
                        )

        # Process ACES for domains (DCSync)
        for ddata in self.domains_data:
            dname = ddata.get("Properties", {}).get("name", domain.name)
            process_aces(dname, "Domain", ddata.get("Aces", []))
            
        # Process ACES for groups
        for gdata in self.groups_data:
            sid = gdata.get("ObjectIdentifier", "")
            if sid in groups_by_sid:
                process_aces(groups_by_sid[sid].name, "Group", gdata.get("Aces", []))
                
        # Process ACES for users
        for udata in self.users_data:
            sid = udata.get("ObjectIdentifier", "")
            if sid in users_by_sid:
                process_aces(users_by_sid[sid].sam_account_name, "User", udata.get("Aces", []))

        # We set random IPs for hosts since BH might not have them
        for i, host in enumerate(manifest.hosts):
            host.ip = f"10.0.1.{10 + i}"

        return manifest

    def _parse_domains(self) -> Domain:
        if not self.domains_data:
            return Domain(name="UNKNOWN.LOCAL", netbios_name="UNKNOWN", default_password_policy="Complex")
        
        props = self.domains_data[0].get("Properties", {})
        fqdn = props.get("name", "UNKNOWN.LOCAL")
        netbios = fqdn.split(".")[0].upper()
        
        return Domain(
            name=fqdn,
            netbios_name=netbios,
            default_password_policy="Complex",
            functional_level=props.get("functionallevel", "Unknown"),
            domain_sid=self.domains_data[0].get("ObjectIdentifier", ""),
        )

    def _load_zip(self) -> None:
        """Extract JSON files from the BloodHound output zip."""
        with zipfile.ZipFile(self.zip_path, "r") as z:
            for filename in z.namelist():
                name_lower = filename.lower()
                if not name_lower.endswith(".json"):
                    continue
                
                with z.open(filename) as f:
                    data = json.load(f)
                    
                    if "users.json" in name_lower:
                        self.users_data = data.get("data", [])
                    elif "computers.json" in name_lower:
                        self.computers_data = data.get("data", [])
                    elif "groups.json" in name_lower:
                        self.groups_data = data.get("data", [])
                    elif "domains.json" in name_lower:
                        self.domains_data = data.get("data", [])
