import networkx as nx
import matplotlib.pyplot as plt
import json
from datetime import datetime
import textwrap

class EntraPrivilegeVisualizer:
    def __init__(self, scan_results):
        self.results = scan_results
        self.graph = nx.DiGraph()
        
    def build_graph(self):
        """Build network graph from scan results"""
        print("📊 Building privilege graph...")
        
        # Add nodes for users
        for user in self.results['users']:
            self.graph.add_node(
                user['name'],
                type='user',
                upn=user['upn']
            )
        
        # Add nodes for groups (only if they have members or roles)
        for group in self.results['groups']:
            self.graph.add_node(
                group['name'],
                type='group'
            )
        
        # Add nodes for admin roles
        admin_roles = set()
        for assignment in self.results['role_assignments']:
            admin_roles.add(assignment['role'])
        
        for role in admin_roles:
            self.graph.add_node(
                role,
                type='role'
            )
        
        # Add edges for role assignments
        for assignment in self.results['role_assignments']:
            self.graph.add_edge(
                assignment['member_name'],
                assignment['role'],
                type='admin_assignment'
            )
        
        print(f"✅ Graph built: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges")
    
    def wrap_label(self, text, width=12):
        """Wrap text to fit in node"""
        # Split on spaces and wrap
        return '\n'.join(textwrap.wrap(text, width=width, break_long_words=False))
    
    def generate_visualization(self, output_file='output/privilege_graph.png'):
        """Generate clean, hierarchical visual graph"""
        print("🎨 Generating visualization...")
        
        # Create larger figure for better readability
        plt.figure(figsize=(24, 16), facecolor='white')
        
        # Separate nodes by type
        users = [n for n, d in self.graph.nodes(data=True) if d.get('type') == 'user']
        groups = [n for n, d in self.graph.nodes(data=True) if d.get('type') == 'group']
        roles = [n for n, d in self.graph.nodes(data=True) if d.get('type') == 'role']
        
        # Use hierarchical layout instead of spring
        # Roles at top, users at bottom, groups in middle
        pos = {}
        
        # Admin roles at the top (centered)
        role_spacing = 2.0
        role_start_x = -(len(roles) - 1) * role_spacing / 2
        for i, role in enumerate(roles):
            pos[role] = (role_start_x + i * role_spacing, 2.0)
        
        # Users at the bottom (spread out)
        user_spacing = 1.5
        user_start_x = -(len(users) - 1) * user_spacing / 2
        for i, user in enumerate(users):
            pos[user] = (user_start_x + i * user_spacing, 0.0)
        
        # Groups in the middle (spread out)
        group_spacing = 1.5
        group_start_x = -(len(groups) - 1) * group_spacing / 2
        for i, group in enumerate(groups):
            pos[group] = (group_start_x + i * group_spacing, 1.0)
        
        # Draw edges first (so they appear behind nodes)
        nx.draw_networkx_edges(
            self.graph, pos,
            edge_color='#34495e',
            arrows=True,
            arrowsize=25,
            width=2.5,
            arrowstyle='->',
            connectionstyle='arc3,rad=0.1',
            alpha=0.6
        )
        
        # Draw user nodes (blue circles) - LARGER to fit text
        nx.draw_networkx_nodes(
            self.graph, pos,
            nodelist=users,
            node_color='#3498db',
            node_size=5000,
            node_shape='o',
            edgecolors='#2c3e50',
            linewidths=2
        )
        
        # Draw group nodes (orange squares) - LARGER to fit text
        nx.draw_networkx_nodes(
            self.graph, pos,
            nodelist=groups,
            node_color='#f39c12',
            node_size=5000,
            node_shape='s',
            edgecolors='#d68910',
            linewidths=2
        )
        
        # Draw role nodes (red diamonds - larger to emphasize)
        nx.draw_networkx_nodes(
            self.graph, pos,
            nodelist=roles,
            node_color='#e74c3c',
            node_size=7000,
            node_shape='D',
            edgecolors='#c0392b',
            linewidths=3
        )
        
        # Wrap labels and draw
        wrapped_labels = {}
        for node in self.graph.nodes():
            node_type = self.graph.nodes[node].get('type')
            
            # Different wrap widths for different node types
            if node_type == 'role':
                wrapped_labels[node] = self.wrap_label(node, width=15)
            elif node_type == 'group':
                wrapped_labels[node] = self.wrap_label(node, width=12)
            else:  # user
                wrapped_labels[node] = self.wrap_label(node, width=12)
        
        nx.draw_networkx_labels(
            self.graph, pos,
            wrapped_labels,
            font_size=9,
            font_weight='bold',
            font_color='white',
            font_family='sans-serif'
        )
        
        # Add title with more info
        plt.title(
            f'Entra ID Privilege Escalation Analysis\n'
            f'{len(users)} Users • {len(groups)} Groups • {len(roles)} Admin Roles\n'
            f'Scan Date: {datetime.now().strftime("%Y-%m-%d %H:%M")}',
            fontsize=18,
            fontweight='bold',
            pad=30,
            color='#2c3e50'
        )
        
        # Add legend
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor='#3498db', edgecolor='#2c3e50', label='Users'),
            Patch(facecolor='#f39c12', edgecolor='#d68910', label='Groups'),
            Patch(facecolor='#e74c3c', edgecolor='#c0392b', label='Admin Roles')
        ]
        plt.legend(
            handles=legend_elements,
            loc='upper left',
            fontsize=13,
            frameon=True,
            fancybox=True,
            shadow=True
        )
        
        # Add findings text box
        findings_text = f"⚠️  Privilege Paths Found: {self.graph.number_of_edges()}"
        plt.text(
            0.02, 0.02,
            findings_text,
            transform=plt.gcf().transFigure,
            fontsize=12,
            bbox=dict(boxstyle='round', facecolor='#ecf0f1', alpha=0.8),
            color='#e74c3c',
            fontweight='bold'
        )
        
        # Remove axes
        plt.axis('off')
        plt.tight_layout()
        
        # Save with high quality
        plt.savefig(output_file, dpi=300, bbox_inches='tight', facecolor='white')
        print(f"✅ Visualization saved to {output_file}")
        
        return output_file

def visualize_from_json(json_file='output/scan_results.json', 
                        output_file='output/privilege_graph.png'):
    """Load results and create visualization"""
    with open(json_file, 'r') as f:
        results = json.load(f)
    
    visualizer = EntraPrivilegeVisualizer(results)
    visualizer.build_graph()
    visualizer.generate_visualization(output_file)
    
    return output_file

if __name__ == "__main__":
    visualize_from_json()
