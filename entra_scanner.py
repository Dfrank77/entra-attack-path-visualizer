import asyncio
import aiohttp
from azure.identity import InteractiveBrowserCredential
from msgraph import GraphServiceClient
from colorama import Fore, Style, init

from entra_security_report import Finding, Subject, Scan, Storage

init(autoreset=True)

TOOL = "attack-path"

TIER_0_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
}

TIER_1_ROLES = {
    "Application Administrator",
    "Cloud Application Administrator",
    "Security Administrator",
    "Conditional Access Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "User Administrator",
}


def _risk_for_role(role_name):
    if role_name in TIER_0_ROLES:
        return "TIER0"
    if role_name in TIER_1_ROLES:
        return "TIER1"
    return "TIER2"


def _severity_from_risk(risk, assignment_type):
    if risk == "TIER0":
        return "critical" if assignment_type == "active" else "high"
    if risk == "TIER1":
        return "high" if assignment_type == "active" else "medium"
    return "medium" if assignment_type == "active" else "low"


class EntraPrivilegeScanner:
    def __init__(self):
        self.scopes = [
            "User.Read.All",
            "Group.Read.All",
            "Directory.Read.All",
            "RoleManagement.Read.All",
            "RoleManagement.Read.Directory",
            "RoleEligibilitySchedule.Read.Directory",
        ]
        self.credential = None
        self.client = None
        self.access_token = None
        self.tenant_id = None

        self.users = []
        self.groups = []
        self.role_assignments = []
        self.pim_eligible_assignments = []
        self.findings = []

        print(f"{Fore.CYAN}Initializing Entra ID Privilege Scanner...{Style.RESET_ALL}")

    async def connect(self):
        print(f"{Fore.YELLOW}Connecting to Microsoft Graph...{Style.RESET_ALL}")
        self.credential = InteractiveBrowserCredential(
            client_id="7be5ba65-ddcd-4ae9-bf94-747a6e38e9ad"
        )
        self.client = GraphServiceClient(credentials=self.credential, scopes=self.scopes)
        token = self.credential.get_token("https://graph.microsoft.com/.default")
        self.access_token = token.token

        # Best-effort tenant ID from the token claims
        import base64, json as _json
        try:
            payload = self.access_token.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            self.tenant_id = _json.loads(base64.urlsafe_b64decode(payload)).get("tid", "unknown")
        except Exception:
            self.tenant_id = "unknown"

        print(f"{Fore.GREEN}Connected to Microsoft Graph{Style.RESET_ALL}")

    async def scan_users(self):
        print(f"\n{Fore.YELLOW}Scanning users...{Style.RESET_ALL}")
        try:
            result = await self.client.users.get()
            self.users = result.value if result.value else []
            while result.odata_next_link:
                result = await self.client.users.with_url(result.odata_next_link).get()
                self.users.extend(result.value if result.value else [])
            print(f"{Fore.GREEN}Found {len(self.users)} users{Style.RESET_ALL}")
            return self.users
        except Exception as e:
            print(f"{Fore.RED}Error scanning users: {e}{Style.RESET_ALL}")
            return []

    async def scan_groups(self):
        print(f"\n{Fore.YELLOW}Scanning groups...{Style.RESET_ALL}")
        try:
            result = await self.client.groups.get()
            self.groups = result.value if result.value else []
            while result.odata_next_link:
                result = await self.client.groups.with_url(result.odata_next_link).get()
                self.groups.extend(result.value if result.value else [])
            print(f"{Fore.GREEN}Found {len(self.groups)} groups{Style.RESET_ALL}")
            return self.groups
        except Exception as e:
            print(f"{Fore.RED}Error scanning groups: {e}{Style.RESET_ALL}")
            return []

    async def scan_directory_roles(self):
        print(f"\n{Fore.YELLOW}Scanning directory roles...{Style.RESET_ALL}")
        try:
            result = await self.client.directory_roles.get()
            roles = result.value if result.value else []
            for role in roles:
                role_name = role.display_name
                members_result = await self.client.directory_roles.by_directory_role_id(role.id).members.get()
                members = members_result.value if members_result.value else []
                for member in members:
                    self.role_assignments.append({
                        "role": role_name,
                        "role_id": role.id,
                        "member_id": member.id,
                        "member_type": type(member).__name__,
                    })
            print(f"{Fore.GREEN}Found {len(self.role_assignments)} active role assignments{Style.RESET_ALL}")
            return self.role_assignments
        except Exception as e:
            print(f"{Fore.RED}Error scanning directory roles: {e}{Style.RESET_ALL}")
            return []

    async def scan_pim_eligible_roles(self):
        print(f"\n{Fore.YELLOW}Scanning PIM eligible role assignments...{Style.RESET_ALL}")
        headers = {"Authorization": f"Bearer {self.access_token}"}
        url = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for assignment in data.get("value", []):
                            role_def_id = assignment.get("roleDefinitionId", "")
                            principal_id = assignment.get("principalId", "")
                            role_def_url = f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/{role_def_id}"
                            async with session.get(role_def_url, headers=headers) as role_resp:
                                if role_resp.status == 200:
                                    role_data = await role_resp.json()
                                    role_name = role_data.get("displayName", "Unknown")
                                    principal_name = "Unknown"
                                    for u in self.users:
                                        if u.id == principal_id:
                                            principal_name = u.display_name
                                            break
                                    for g in self.groups:
                                        if g.id == principal_id:
                                            principal_name = g.display_name
                                            break
                                    self.pim_eligible_assignments.append({
                                        "role": role_name,
                                        "member_id": principal_id,
                                        "member_name": principal_name,
                                        "assignment_type": "eligible",
                                    })
                    elif resp.status == 403:
                        print(f"{Fore.YELLOW}PIM access denied. Check permissions.{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Found {len(self.pim_eligible_assignments)} PIM eligible assignments{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error scanning PIM: {e}{Style.RESET_ALL}")
        return self.pim_eligible_assignments

    async def analyze_privilege_paths(self):
        print(f"\n{Fore.YELLOW}Analyzing privilege escalation paths...{Style.RESET_ALL}")

        # Active assignments: direct or via group membership
        for assignment in self.role_assignments:
            role_name = assignment["role"]
            member_id = assignment["member_id"]
            risk = _risk_for_role(role_name)

            member_name = "Unknown"
            is_group = False
            for u in self.users:
                if u.id == member_id:
                    member_name = u.display_name
                    break
            else:
                for g in self.groups:
                    if g.id == member_id:
                        member_name = g.display_name
                        is_group = True
                        break

            if is_group:
                try:
                    members_result = await self.client.groups.by_group_id(member_id).members.get()
                    members = members_result.value if members_result.value else []
                    for member in members:
                        display_name = getattr(member, "display_name", "Unknown")
                        self.findings.append(self._path_finding(
                            path_type="group_membership",
                            assignment_type="active",
                            risk=risk,
                            user_name=display_name,
                            user_id=member.id,
                            role_name=role_name,
                            path=[display_name, member_name, role_name],
                        ))
                except Exception as e:
                    print(f"   {Fore.YELLOW}Could not read members of {member_name}: {e}{Style.RESET_ALL}")
            else:
                self.findings.append(self._path_finding(
                    path_type="direct_assignment",
                    assignment_type="active",
                    risk=risk,
                    user_name=member_name,
                    user_id=member_id,
                    role_name=role_name,
                    path=[member_name, role_name],
                ))

        # PIM eligible assignments
        for assignment in self.pim_eligible_assignments:
            role_name = assignment["role"]
            member_id = assignment["member_id"]
            member_name = assignment["member_name"]
            risk = _risk_for_role(role_name)

            is_group = any(g.id == member_id for g in self.groups)
            if is_group:
                try:
                    members_result = await self.client.groups.by_group_id(member_id).members.get()
                    members = members_result.value if members_result.value else []
                    for member in members:
                        display_name = getattr(member, "display_name", "Unknown")
                        self.findings.append(self._path_finding(
                            path_type="pim_eligible_via_group",
                            assignment_type="eligible",
                            risk=risk,
                            user_name=display_name,
                            user_id=member.id,
                            role_name=role_name,
                            path=[display_name, member_name, role_name],
                        ))
                except Exception:
                    pass
            else:
                self.findings.append(self._path_finding(
                    path_type="pim_eligible_direct",
                    assignment_type="eligible",
                    risk=risk,
                    user_name=member_name,
                    user_id=member_id,
                    role_name=role_name,
                    path=[member_name, role_name],
                ))

        active_count = sum(1 for f in self.findings if f.evidence.get("assignment_type") == "active")
        eligible_count = sum(1 for f in self.findings if f.evidence.get("assignment_type") == "eligible")
        print(f"\n{Fore.GREEN}Found {len(self.findings)} privilege paths ({active_count} active, {eligible_count} PIM eligible){Style.RESET_ALL}")
        return self.findings

    def _path_finding(self, path_type, assignment_type, risk, user_name, user_id, role_name, path):
        rule_map = {
            "direct_assignment": "direct-role-assignment",
            "group_membership": "transitive-role-via-group",
            "pim_eligible_direct": "pim-eligible-direct",
            "pim_eligible_via_group": "pim-eligible-via-group",
        }
        title_map = {
            "direct_assignment": f"{user_name} holds {role_name}",
            "group_membership": f"{user_name} inherits {role_name} via {path[1] if len(path) > 2 else 'group'}",
            "pim_eligible_direct": f"{user_name} PIM-eligible for {role_name}",
            "pim_eligible_via_group": f"{user_name} PIM-eligible for {role_name} via {path[1] if len(path) > 2 else 'group'}",
        }
        detail_map = {
            "direct_assignment": f"Direct role assignment to {role_name}.",
            "group_membership": f"Reaches {role_name} through group membership in {path[1] if len(path) > 2 else 'a privileged group'}.",
            "pim_eligible_direct": f"Dormant privilege: can activate {role_name} at any time.",
            "pim_eligible_via_group": f"Dormant privilege: group membership grants activation rights for {role_name}.",
        }
        return Finding(
            tool=TOOL,
            rule=rule_map[path_type],
            severity=_severity_from_risk(risk, assignment_type),
            subject=Subject(type="user", id=user_id, display_name=user_name),
            title=title_map[path_type],
            detail=detail_map[path_type],
            evidence={
                "path": path,
                "path_type": path_type,
                "assignment_type": assignment_type,
                "risk": risk,
                "role": role_name,
            },
        )

    def persist(self):
        """Write findings and scan record to shared storage."""
        storage = Storage(".findings")
        scan = Scan(tool=TOOL, tenant_id=self.tenant_id)
        storage.record_scan(scan, self.findings)
        return storage

    async def run_scan(self):
        await self.connect()
        await self.scan_users()
        await self.scan_groups()
        await self.scan_directory_roles()
        await self.scan_pim_eligible_roles()
        await self.analyze_privilege_paths()

        storage = self.persist()

        print(f"\n{Fore.CYAN}Scan Summary:{Style.RESET_ALL}")
        print(f"  Users: {len(self.users)}")
        print(f"  Groups: {len(self.groups)}")
        print(f"  Active Role Assignments: {len(self.role_assignments)}")
        print(f"  PIM Eligible Assignments: {len(self.pim_eligible_assignments)}")
        print(f"  Findings: {len(self.findings)}")
        return storage


async def main():
    scanner = EntraPrivilegeScanner()
    await scanner.run_scan()


if __name__ == "__main__":
    asyncio.run(main())