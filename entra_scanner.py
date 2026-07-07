import asyncio
from azure.identity import InteractiveBrowserCredential
from msgraph import GraphServiceClient
from colorama import Fore, Style, init
import json
import aiohttp

# Initialize colorama for colored output
init(autoreset=True)

class EntraPrivilegeScanner:
    def __init__(self):
        self.scopes = [
            "User.Read.All",
            "Group.Read.All",
            "Directory.Read.All",
            "RoleManagement.Read.All",
            "RoleManagement.Read.Directory",
            "RoleEligibilitySchedule.Read.Directory"
        ]

        self.credential = None
        self.client = None
        self.access_token = None

        self.users = []
        self.groups = []
        self.role_assignments = []
        self.pim_eligible_assignments = []
        self.privilege_paths = []

        print(f"{Fore.CYAN}Initializing Entra ID Privilege Scanner...{Style.RESET_ALL}")

    async def connect(self):
        """Authenticate to Microsoft Graph"""
        print(f"{Fore.YELLOW}Connecting to Microsoft Graph...{Style.RESET_ALL}")

        self.credential = InteractiveBrowserCredential(
            client_id="7be5ba65-ddcd-4ae9-bf94-747a6e38e9ad"
        )

        self.client = GraphServiceClient(
            credentials=self.credential,
            scopes=self.scopes
        )

        # Also get a raw token for REST calls the SDK doesn't support well
        token = self.credential.get_token("https://graph.microsoft.com/.default")
        self.access_token = token.token

        print(f"{Fore.GREEN}Connected to Microsoft Graph{Style.RESET_ALL}")

    async def scan_users(self):
        """Get all users in the tenant"""
        print(f"\n{Fore.YELLOW}Scanning users...{Style.RESET_ALL}")

        try:
            result = await self.client.users.get()
            self.users = result.value if result.value else []
            while result.odata_next_link:
                result = await self.client.users.with_url(result.odata_next_link).get()
                self.users.extend(result.value if result.value else [])

            print(f"{Fore.GREEN}Found {len(self.users)} users{Style.RESET_ALL}")

            for user in self.users:
                print(f"   - {user.display_name} ({user.user_principal_name})")

            return self.users
        except Exception as e:
            print(f"{Fore.RED}Error scanning users: {e}{Style.RESET_ALL}")
            return []

    async def scan_groups(self):
        """Get all groups in the tenant"""
        print(f"\n{Fore.YELLOW}Scanning groups...{Style.RESET_ALL}")

        try:
            result = await self.client.groups.get()
            self.groups = result.value if result.value else []
            while result.odata_next_link:
                result = await self.client.groups.with_url(result.odata_next_link).get()
                self.groups.extend(result.value if result.value else [])

            print(f"{Fore.GREEN}Found {len(self.groups)} groups{Style.RESET_ALL}")

            for group in self.groups:
                print(f"   - {group.display_name}")

            return self.groups
        except Exception as e:
            print(f"{Fore.RED}Error scanning groups: {e}{Style.RESET_ALL}")
            return []

    async def scan_directory_roles(self):
        """Get all directory role assignments"""
        print(f"\n{Fore.YELLOW}Scanning directory roles...{Style.RESET_ALL}")

        try:
            result = await self.client.directory_roles.get()
            roles = result.value if result.value else []

            print(f"{Fore.GREEN}Found {len(roles)} active directory roles{Style.RESET_ALL}")

            for role in roles:
                try:
                    members_result = await self.client.directory_roles.by_directory_role_id(role.id).members.get()
                    members = members_result.value if members_result.value else []

                    if members:
                        print(f"\n   {Fore.CYAN}{role.display_name}:{Style.RESET_ALL}")
                        for member in members:
                            if hasattr(member, 'display_name'):
                                print(f"      -> {member.display_name}")
                            else:
                                print(f"      -> {member.id}")

                        for member in members:
                            self.role_assignments.append({
                                'role': role.display_name,
                                'role_id': role.id,
                                'member_id': member.id,
                                'member_name': getattr(member, 'display_name', 'Unknown'),
                                'assignment_type': 'active'
                            })

                except Exception as e:
                    print(f"      {Fore.YELLOW}Could not read members: {e}{Style.RESET_ALL}")

            return self.role_assignments

        except Exception as e:
            print(f"{Fore.RED}Error scanning directory roles: {e}{Style.RESET_ALL}")
            return []

    async def scan_pim_eligible_roles(self):
        """Scan for PIM eligible role assignments using REST API"""
        print(f"\n{Fore.YELLOW}Scanning PIM eligible role assignments...{Style.RESET_ALL}")

        try:
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }

            # Get role definitions first for name mapping
            role_defs = {}
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions",
                    headers=headers
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for rd in data.get("value", []):
                            role_defs[rd["id"]] = rd["displayName"]

                # Get eligible assignments
                async with session.get(
                    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$expand=principal,roleDefinition",
                    headers=headers
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        eligible = data.get("value", [])

                        print(f"{Fore.GREEN}Found {len(eligible)} PIM eligible assignments{Style.RESET_ALL}")

                        for assignment in eligible:
                            principal = assignment.get("principal", {})
                            role_def = assignment.get("roleDefinition", {})
                            principal_name = principal.get("displayName", "Unknown")
                            role_name = role_def.get("displayName", role_defs.get(assignment.get("roleDefinitionId", ""), "Unknown Role"))
                            principal_id = assignment.get("principalId", "")

                            print(f"   {Fore.MAGENTA}[ELIGIBLE] {principal_name} -> {role_name}{Style.RESET_ALL}")

                            self.pim_eligible_assignments.append({
                                'role': role_name,
                                'role_definition_id': assignment.get("roleDefinitionId", ""),
                                'member_id': principal_id,
                                'member_name': principal_name,
                                'assignment_type': 'eligible',
                                'status': assignment.get("status", ""),
                                'member_type': assignment.get("memberType", "")
                            })
                    elif resp.status == 403:
                        print(f"{Fore.YELLOW}PIM access denied. Check RoleEligibilitySchedule.Read.Directory permission.{Style.RESET_ALL}")
                    else:
                        text = await resp.text()
                        print(f"{Fore.RED}PIM scan failed ({resp.status}): {text}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}Error scanning PIM eligible roles: {e}{Style.RESET_ALL}")

        return self.pim_eligible_assignments

    async def analyze_privilege_paths(self):
        """Analyze privilege escalation paths through group memberships and PIM"""
        print(f"\n{Fore.YELLOW}Analyzing privilege escalation paths...{Style.RESET_ALL}")

        # Privileged roles to flag
        privileged_roles = [
            'Global Administrator',
            'Privileged Role Administrator',
            'User Administrator',
            'Security Administrator',
            'Exchange Administrator',
            'SharePoint Administrator',
            'Intune Administrator',
            'Application Administrator',
            'Cloud Application Administrator',
            'Authentication Administrator',
            'Helpdesk Administrator',
            'Password Administrator',
            'Conditional Access Administrator',
            'Groups Administrator'
        ]

        high_risk_roles = [
            'Global Administrator',
            'Privileged Role Administrator',
            'Application Administrator',
            'Cloud Application Administrator',
            'Authentication Administrator'
        ]

        group_map = {g.id: g.display_name for g in self.groups}

        # Analyze active role assignments
        for assignment in self.role_assignments:
            if assignment['role'] not in privileged_roles:
                continue

            member_id = assignment['member_id']
            member_name = assignment['member_name']
            risk = 'HIGH' if assignment['role'] in high_risk_roles else 'MEDIUM'

            is_group = any(g.id == member_id for g in self.groups)

            if is_group:
                try:
                    members_result = await self.client.groups.by_group_id(member_id).members.get()
                    members = members_result.value if members_result.value else []

                    for member in members:
                        display_name = getattr(member, 'display_name', 'Unknown')
                        self.privilege_paths.append({
                            'user': display_name,
                            'user_id': member.id,
                            'role': assignment['role'],
                            'path': [display_name, member_name, assignment['role']],
                            'path_type': 'group_membership',
                            'assignment_type': 'active',
                            'risk': risk
                        })
                        print(f"   {Fore.RED}[ACTIVE] {display_name} -> {member_name} -> {assignment['role']} (Risk: {risk}){Style.RESET_ALL}")

                except Exception as e:
                    print(f"   {Fore.YELLOW}Could not read members of {member_name}: {e}{Style.RESET_ALL}")

            else:
                self.privilege_paths.append({
                    'user': member_name,
                    'user_id': member_id,
                    'role': assignment['role'],
                    'path': [member_name, assignment['role']],
                    'path_type': 'direct_assignment',
                    'assignment_type': 'active',
                    'risk': risk
                })
                print(f"   {Fore.RED}[ACTIVE] {member_name} -> {assignment['role']} (Risk: {risk}){Style.RESET_ALL}")

        # Analyze PIM eligible assignments
        for assignment in self.pim_eligible_assignments:
            if assignment['role'] not in privileged_roles:
                continue

            risk = 'HIGH' if assignment['role'] in high_risk_roles else 'MEDIUM'
            member_name = assignment['member_name']
            member_id = assignment['member_id']

            is_group = any(g.id == member_id for g in self.groups)

            if is_group:
                try:
                    members_result = await self.client.groups.by_group_id(member_id).members.get()
                    members = members_result.value if members_result.value else []

                    for member in members:
                        display_name = getattr(member, 'display_name', 'Unknown')
                        self.privilege_paths.append({
                            'user': display_name,
                            'user_id': member.id,
                            'role': assignment['role'],
                            'path': [display_name, member_name, assignment['role']],
                            'path_type': 'pim_eligible_via_group',
                            'assignment_type': 'eligible',
                            'risk': risk
                        })
                        print(f"   {Fore.MAGENTA}[PIM ELIGIBLE] {display_name} -> {member_name} -> {assignment['role']} (Risk: {risk}){Style.RESET_ALL}")

                except Exception as e:
                    print(f"   {Fore.YELLOW}Could not read members of {member_name}: {e}{Style.RESET_ALL}")
            else:
                self.privilege_paths.append({
                    'user': member_name,
                    'user_id': member_id,
                    'role': assignment['role'],
                    'path': [member_name, assignment['role']],
                    'path_type': 'pim_eligible_direct',
                    'assignment_type': 'eligible',
                    'risk': risk
                })
                print(f"   {Fore.MAGENTA}[PIM ELIGIBLE] {member_name} -> {assignment['role']} (Risk: {risk}){Style.RESET_ALL}")

        active_count = len([p for p in self.privilege_paths if p['assignment_type'] == 'active'])
        eligible_count = len([p for p in self.privilege_paths if p['assignment_type'] == 'eligible'])
        print(f"\n{Fore.GREEN}Found {len(self.privilege_paths)} total privilege paths ({active_count} active, {eligible_count} PIM eligible){Style.RESET_ALL}")
        return self.privilege_paths

    def export_results(self, filename='output/scan_results.json'):
        """Export scan results to JSON"""
        print(f"\n{Fore.YELLOW}Exporting results...{Style.RESET_ALL}")

        active_paths = [p for p in self.privilege_paths if p['assignment_type'] == 'active']
        eligible_paths = [p for p in self.privilege_paths if p['assignment_type'] == 'eligible']

        results = {
            'summary': {
                'total_users': len(self.users),
                'total_groups': len(self.groups),
                'total_active_assignments': len(self.role_assignments),
                'total_pim_eligible': len(self.pim_eligible_assignments),
                'privilege_paths_found': len(self.privilege_paths),
                'active_paths': len(active_paths),
                'eligible_paths': len(eligible_paths),
                'high_risk_paths': len([p for p in self.privilege_paths if p['risk'] == 'HIGH']),
                'medium_risk_paths': len([p for p in self.privilege_paths if p['risk'] == 'MEDIUM'])
            },
            'users': [
                {
                    'name': user.display_name,
                    'upn': user.user_principal_name,
                    'id': user.id
                }
                for user in self.users
            ],
            'groups': [
                {
                    'name': group.display_name,
                    'id': group.id
                }
                for group in self.groups
            ],
            'role_assignments': self.role_assignments,
            'pim_eligible_assignments': self.pim_eligible_assignments,
            'privilege_paths': self.privilege_paths
        }

        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)

        print(f"{Fore.GREEN}Results exported to {filename}{Style.RESET_ALL}")
        return results

    async def run_scan(self):
        """Run complete scan"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  ENTRA ID PRIVILEGE ESCALATION ANALYZER{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

        await self.connect()
        await self.scan_users()
        await self.scan_groups()
        await self.scan_directory_roles()
        await self.scan_pim_eligible_roles()
        await self.analyze_privilege_paths()

        results = self.export_results()

        active_paths = results['summary']['active_paths']
        eligible_paths = results['summary']['eligible_paths']
        high_risk = results['summary']['high_risk_paths']

        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  SCAN COMPLETE{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"\n{Fore.WHITE}Summary:{Style.RESET_ALL}")
        print(f"  Total Users: {len(self.users)}")
        print(f"  Total Groups: {len(self.groups)}")
        print(f"  Active Role Assignments: {len(self.role_assignments)}")
        print(f"  PIM Eligible Assignments: {len(self.pim_eligible_assignments)}")
        print(f"  Privilege Paths Found: {len(self.privilege_paths)}")
        print(f"    Active: {active_paths}")
        print(f"    PIM Eligible: {eligible_paths}")
        print(f"    High Risk: {high_risk}\n")

        return results

# Main execution
async def main():
    scanner = EntraPrivilegeScanner()
    await scanner.run_scan()

if __name__ == "__main__":
    asyncio.run(main())
