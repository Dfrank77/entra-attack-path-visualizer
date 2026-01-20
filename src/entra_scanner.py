import asyncio
from azure.identity import InteractiveBrowserCredential
from msgraph import GraphServiceClient
from colorama import Fore, Style, init
import json

# Initialize colorama for colored output
init(autoreset=True)

class EntraPrivilegeScanner:
    def __init__(self):
        self.scopes = [
            "User.Read.All",
            "Group.Read.All",
            "Directory.Read.All",
            "RoleManagement.Read.All"
        ]
        
        self.credential = None
        self.client = None
        
        self.users = []
        self.groups = []
        self.role_assignments = []
        self.privilege_paths = []
        
        print(f"{Fore.CYAN}🔍 Initializing Entra ID Privilege Scanner...{Style.RESET_ALL}")
    
    async def connect(self):
        """Authenticate to Microsoft Graph"""
        print(f"{Fore.YELLOW}🔐 Connecting to Microsoft Graph...{Style.RESET_ALL}")
        
        # Create credential
        self.credential = InteractiveBrowserCredential(
            client_id="14d82eec-204b-4c2f-b7e8-296a70dab67e"
        )
        
        # Create Graph client
        self.client = GraphServiceClient(
            credentials=self.credential,
            scopes=self.scopes
        )
        
        print(f"{Fore.GREEN}✅ Connected to Microsoft Graph{Style.RESET_ALL}")
    
    async def scan_users(self):
        """Get all users in the tenant"""
        print(f"\n{Fore.YELLOW}👥 Scanning users...{Style.RESET_ALL}")
        
        try:
            result = await self.client.users.get()
            self.users = result.value if result.value else []
            
            print(f"{Fore.GREEN}✅ Found {len(self.users)} users{Style.RESET_ALL}")
            
            # Store user info
            for user in self.users:
                print(f"   - {user.display_name} ({user.user_principal_name})")
            
            return self.users
        except Exception as e:
            print(f"{Fore.RED}❌ Error scanning users: {e}{Style.RESET_ALL}")
            return []
    
    async def scan_groups(self):
        """Get all groups in the tenant"""
        print(f"\n{Fore.YELLOW}👥 Scanning groups...{Style.RESET_ALL}")
        
        try:
            result = await self.client.groups.get()
            self.groups = result.value if result.value else []
            
            print(f"{Fore.GREEN}✅ Found {len(self.groups)} groups{Style.RESET_ALL}")
            
            for group in self.groups:
                print(f"   - {group.display_name}")
            
            return self.groups
        except Exception as e:
            print(f"{Fore.RED}❌ Error scanning groups: {e}{Style.RESET_ALL}")
            return []
    
    async def scan_directory_roles(self):
        """Get all directory role assignments"""
        print(f"\n{Fore.YELLOW}👑 Scanning directory roles...{Style.RESET_ALL}")
        
        try:
            result = await self.client.directory_roles.get()
            roles = result.value if result.value else []
            
            print(f"{Fore.GREEN}✅ Found {len(roles)} active directory roles{Style.RESET_ALL}")
            
            # For each role, get members
            for role in roles:
                try:
                    members_result = await self.client.directory_roles.by_directory_role_id(role.id).members.get()
                    members = members_result.value if members_result.value else []
                    
                    if members:
                        print(f"\n   {Fore.CYAN}{role.display_name}:{Style.RESET_ALL}")
                        for member in members:
                            # Try to get display name
                            if hasattr(member, 'display_name'):
                                print(f"      → {member.display_name}")
                            else:
                                print(f"      → {member.id}")
                        
                        # Store assignment
                        for member in members:
                            self.role_assignments.append({
                                'role': role.display_name,
                                'role_id': role.id,
                                'member_id': member.id,
                                'member_name': getattr(member, 'display_name', 'Unknown')
                            })
                
                except Exception as e:
                    print(f"      {Fore.YELLOW}⚠️  Could not read members: {e}{Style.RESET_ALL}")
            
            return self.role_assignments
        
        except Exception as e:
            print(f"{Fore.RED}❌ Error scanning directory roles: {e}{Style.RESET_ALL}")
            return []
    
    async def analyze_privilege_paths(self):
        """Analyze privilege escalation paths through group memberships"""
        print(f"\n{Fore.YELLOW}🔍 Analyzing privilege escalation paths...{Style.RESET_ALL}")
        
        # For now, just identify users with admin roles
        admin_roles = [
            'Global Administrator',
            'Privileged Role Administrator',
            'User Administrator',
            'Security Administrator'
        ]
        
        for assignment in self.role_assignments:
            if assignment['role'] in admin_roles:
                self.privilege_paths.append({
                    'user': assignment['member_name'],
                    'user_id': assignment['member_id'],
                    'role': assignment['role'],
                    'path': [assignment['member_name'], assignment['role']],
                    'risk': 'HIGH' if assignment['role'] == 'Global Administrator' else 'MEDIUM'
                })
        
        print(f"{Fore.GREEN}✅ Found {len(self.privilege_paths)} users with admin access{Style.RESET_ALL}")
        
        for path in self.privilege_paths:
            print(f"   {Fore.RED}⚠️  {path['user']} → {path['role']} (Risk: {path['risk']}){Style.RESET_ALL}")
        
        return self.privilege_paths
    
    def export_results(self, filename='output/scan_results.json'):
        """Export scan results to JSON"""
        print(f"\n{Fore.YELLOW}💾 Exporting results...{Style.RESET_ALL}")
        
        results = {
            'summary': {
                'total_users': len(self.users),
                'total_groups': len(self.groups),
                'admin_count': len(self.privilege_paths),
                'privilege_paths_found': len(self.privilege_paths)
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
            'privilege_paths': self.privilege_paths
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"{Fore.GREEN}✅ Results exported to {filename}{Style.RESET_ALL}")
        return results
    
    async def run_scan(self):
        """Run complete scan"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  ENTRA ID PRIVILEGE ESCALATION ANALYZER{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        # Connect
        await self.connect()
        
        # Scan
        await self.scan_users()
        await self.scan_groups()
        await self.scan_directory_roles()
        
        # Analyze
        await self.analyze_privilege_paths()
        
        # Export
        results = self.export_results()
        
        # Summary
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  SCAN COMPLETE{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"\n{Fore.WHITE}Summary:{Style.RESET_ALL}")
        print(f"  • Total Users: {len(self.users)}")
        print(f"  • Total Groups: {len(self.groups)}")
        print(f"  • Admin Entities: {len(self.privilege_paths)}")
        print(f"  • Privilege Paths Found: {len(self.privilege_paths)}\n")
        
        return results

# Main execution
async def main():
    scanner = EntraPrivilegeScanner()
    await scanner.run_scan()

if __name__ == "__main__":
    asyncio.run(main())
