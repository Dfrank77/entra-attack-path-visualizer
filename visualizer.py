from pyvis.network import Network
import json
import os
from datetime import datetime


class EntraPrivilegeVisualizer:
    def __init__(self, scan_file='output/scan_results.json'):
        with open(scan_file, 'r') as f:
            self.results = json.load(f)

    def generate_visualization(self, output_file='output/privilege_graph.html'):
        """Generate interactive HTML privilege escalation graph"""
        print("Building interactive privilege graph...")

        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)

        net = Network(
            height='900px', width='100%',
            bgcolor='#0d1117', font_color='#e6edf3',
            directed=True, select_menu=False, filter_menu=False
        )

        net.set_options("""
        {
          "physics": {
            "enabled": true,
            "hierarchicalRepulsion": {
              "centralGravity": 0.0,
              "springLength": 200,
              "springConstant": 0.01,
              "nodeDistance": 180,
              "damping": 0.09
            },
            "solver": "hierarchicalRepulsion",
            "stabilization": { "enabled": true, "iterations": 500 }
          },
          "layout": {
            "hierarchical": {
              "enabled": true,
              "direction": "UD",
              "sortMethod": "directed",
              "levelSeparation": 250,
              "nodeSpacing": 200,
              "treeSpacing": 300
            }
          },
          "edges": {
            "smooth": {
              "type": "cubicBezier",
              "forceDirection": "vertical",
              "roundness": 0.4
            }
          },
          "interaction": {
            "hover": true,
            "tooltipDelay": 100,
            "navigationButtons": true
          }
        }
        """)

        paths = self.results.get('privilege_paths', [])
        pim_eligible = self.results.get('pim_eligible_assignments', [])
        summary = self.results.get('summary', {})
        users_list = self.results.get('users', [])

        # Build UPN lookup
        upn_map = {u['name']: u.get('upn', '') for u in users_list}

        added_nodes = set()
        edges_to_add = []

        for path_entry in paths:
            path = path_entry['path']
            risk = path_entry.get('risk', 'MEDIUM')
            assignment_type = path_entry.get('assignment_type', 'active')
            path_type = path_entry.get('path_type', 'direct_assignment')

            if len(path) == 2:
                user_name, role_name = path[0], path[1]
                self._add_user_node(net, user_name, upn_map, added_nodes)
                self._add_role_node(net, role_name, risk, added_nodes)
                edges_to_add.append((user_name, role_name, risk, assignment_type, path_type))

            elif len(path) == 3:
                user_name, group_name, role_name = path[0], path[1], path[2]
                self._add_user_node(net, user_name, upn_map, added_nodes)
                self._add_group_node(net, group_name, added_nodes)
                self._add_role_node(net, role_name, risk, added_nodes)
                edges_to_add.append((user_name, group_name, risk, assignment_type, 'group_member'))
                edges_to_add.append((group_name, role_name, risk, assignment_type, path_type))

        # Deduplicate and add edges
        seen_edges = set()
        for src, dst, risk, assignment_type, ptype in edges_to_add:
            edge_key = f"{src}|{dst}|{assignment_type}"
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)

            if assignment_type == 'eligible':
                color = '#bc8cff' if risk == 'HIGH' else '#9d7aed'
                dashes = True
                width = 3
            else:
                color = '#f85149' if risk == 'HIGH' else '#d29922'
                dashes = False
                width = 3 if risk == 'HIGH' else 2

            net.add_edge(
                src, dst,
                color=color, width=width, dashes=dashes,
                arrows={'to': {'enabled': True, 'scaleFactor': 1.2}},
                title=f"{src} &rarr; {dst}<br>Type: {assignment_type}<br>Risk: {risk}"
            )

        # Generate HTML
        net.save_graph(output_file)

        # Inject summary overlay and title
        self._inject_overlay(output_file, summary, paths, pim_eligible)

        print(f"Visualization saved to {output_file}")
        print("Open in a browser to interact with the graph.")

    def _add_user_node(self, net, name, upn_map, added):
        if name in added:
            return
        upn = upn_map.get(name, '')
        net.add_node(
            name, label=name, shape='dot', size=30,
            color={'background': '#0d419d', 'border': '#58a6ff',
                   'highlight': {'background': '#1a5cc8', 'border': '#79c0ff'}},
            borderWidth=3,
            font={'size': 14, 'color': '#e6edf3', 'face': 'monospace'},
            level=2,
            title=f"<b>{name}</b><br>UPN: {upn}<br>Type: User"
        )
        added.add(name)

    def _add_group_node(self, net, name, added):
        if name in added:
            return
        net.add_node(
            name, label=name, shape='square', size=30,
            color={'background': '#6e3a00', 'border': '#d29922',
                   'highlight': {'background': '#8a4a00', 'border': '#e3b341'}},
            borderWidth=3,
            font={'size': 14, 'color': '#e6edf3', 'face': 'monospace'},
            level=1,
            title=f"<b>{name}</b><br>Type: Group"
        )
        added.add(name)

    def _add_role_node(self, net, name, risk, added):
        if name in added:
            return
        bg = '#b62324' if risk == 'HIGH' else '#7a3000'
        border = '#f85149' if risk == 'HIGH' else '#d29922'
        net.add_node(
            name, label=name, shape='diamond', size=35,
            color={'background': bg, 'border': border,
                   'highlight': {'background': '#d13438', 'border': '#ff7b72'}},
            borderWidth=3,
            font={'size': 14, 'color': '#e6edf3', 'face': 'monospace'},
            level=0,
            title=f"<b>{name}</b><br>Type: Admin Role<br>Risk: {risk}"
        )
        added.add(name)

    def _inject_overlay(self, output_file, summary, paths, pim_eligible):
        """Inject the summary panel and title bar into the HTML"""

        high_html = ''
        for p in [p for p in paths if p.get('risk') == 'HIGH']:
            atype = p.get('assignment_type', 'active')
            tag = '<span style="color:#bc8cff">[PIM]</span>' if atype == 'eligible' else '<span style="color:#f85149">[ACT]</span>'
            path_str = ' &rarr; '.join(p['path'])
            high_html += f'<div style="margin:3px 0;font-size:12px">{tag} {path_str}</div>'

        pim_html = ''
        for p in pim_eligible:
            name = p.get("member_name", "?")
            role = p.get("role", "?")
            pim_html += f'<div style="margin:3px 0;font-size:12px"><span style="color:#e6edf3">{name}</span> <span style="color:#bc8cff">&rarr; {role}</span></div>'

        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M")

        overlay = f"""
        <div style="position:fixed;top:0;left:0;right:0;height:50px;background:#0d1117;
             border-bottom:1px solid #30363d;display:flex;align-items:center;
             justify-content:center;z-index:9998;font-family:monospace">
          <span style="font-size:20px;font-weight:bold;color:#e6edf3">ENTRA ID PRIVILEGE ESCALATION MAP</span>
          <span style="font-size:12px;color:#8b949e;margin-left:20px">Scan: {scan_time}</span>
        </div>

        <div style="position:fixed;top:60px;right:15px;background:#161b22;border:1px solid #30363d;
             border-radius:8px;padding:18px 22px;font-family:monospace;color:#e6edf3;width:320px;
             max-height:calc(100vh - 80px);overflow-y:auto;z-index:9999;
             box-shadow:0 4px 20px rgba(0,0,0,0.5)">

          <div style="font-size:16px;font-weight:bold;text-align:center;margin-bottom:10px">RISK SUMMARY</div>
          <hr style="border-color:#30363d;margin:8px 0">

          <div style="display:flex;justify-content:space-between;margin:4px 0"><span style="color:#8b949e">Total Users</span><b>{summary.get('total_users',0)}</b></div>
          <div style="display:flex;justify-content:space-between;margin:4px 0"><span style="color:#8b949e">Total Groups</span><b>{summary.get('total_groups',0)}</b></div>
          <div style="display:flex;justify-content:space-between;margin:4px 0"><span style="color:#8b949e">Active Assignments</span><b>{summary.get('total_active_assignments',0)}</b></div>
          <div style="display:flex;justify-content:space-between;margin:4px 0"><span style="color:#8b949e">PIM Eligible</span><b style="color:#bc8cff">{summary.get('total_pim_eligible',0)}</b></div>

          <hr style="border-color:#30363d;margin:10px 0">
          <div style="font-size:14px;font-weight:bold;text-align:center;margin-bottom:6px">PRIVILEGE PATHS</div>

          <div style="display:flex;justify-content:space-between;margin:4px 0"><span style="color:#8b949e">Total Paths</span><b>{summary.get('privilege_paths_found',0)}</b></div>
          <div style="display:flex;justify-content:space-between;margin:4px 0"><span style="color:#8b949e">HIGH Risk</span><b style="color:#f85149">{summary.get('high_risk_paths',0)}</b></div>
          <div style="display:flex;justify-content:space-between;margin:4px 0"><span style="color:#8b949e">MEDIUM Risk</span><b style="color:#d29922">{summary.get('medium_risk_paths',0)}</b></div>
          <div style="display:flex;justify-content:space-between;margin:4px 0"><span style="color:#8b949e">Active</span><b style="color:#f85149">{summary.get('active_paths',0)}</b></div>
          <div style="display:flex;justify-content:space-between;margin:4px 0"><span style="color:#8b949e">PIM Eligible</span><b style="color:#bc8cff">{summary.get('eligible_paths',0)}</b></div>

          <hr style="border-color:#30363d;margin:10px 0">
          <div style="font-size:13px;font-weight:bold;text-align:center;color:#f85149;margin-bottom:6px">HIGH RISK PATHS</div>
          {high_html}

          <hr style="border-color:#30363d;margin:10px 0">
          <div style="font-size:13px;font-weight:bold;text-align:center;color:#bc8cff;margin-bottom:6px">PIM ELIGIBLE ROLES</div>
          {pim_html}
        </div>

        <div style="position:fixed;bottom:15px;left:15px;background:#161b22;border:1px solid #30363d;
             border-radius:8px;padding:14px 18px;font-family:monospace;color:#e6edf3;
             z-index:9999;box-shadow:0 4px 20px rgba(0,0,0,0.5)">
          <div style="font-size:12px;font-weight:bold;color:#8b949e;margin-bottom:8px;text-align:center">LEGEND</div>
          <div style="margin:3px 0;font-size:11px"><span style="color:#f85149">&#9473;&#9473;&#9473;</span> Active HIGH risk</div>
          <div style="margin:3px 0;font-size:11px"><span style="color:#d29922">&#9473;&#9473;&#9473;</span> Active MEDIUM risk</div>
          <div style="margin:3px 0;font-size:11px"><span style="color:#bc8cff">- - - -</span> PIM eligible (HIGH)</div>
          <div style="margin:3px 0;font-size:11px"><span style="color:#9d7aed">- - - -</span> PIM eligible (MEDIUM)</div>
          <div style="margin:8px 0 2px 0;border-top:1px solid #30363d;padding-top:6px">
            <div style="margin:3px 0;font-size:11px"><span style="display:inline-block;width:12px;height:12px;background:#b62324;border:2px solid #f85149;border-radius:2px;vertical-align:middle"></span> Admin Role</div>
            <div style="margin:3px 0;font-size:11px"><span style="display:inline-block;width:12px;height:12px;background:#6e3a00;border:2px solid #d29922;vertical-align:middle"></span> Group</div>
            <div style="margin:3px 0;font-size:11px"><span style="display:inline-block;width:12px;height:12px;background:#0d419d;border:2px solid #58a6ff;border-radius:50%;vertical-align:middle"></span> User</div>
          </div>
        </div>
        """

        with open(output_file, 'r') as f:
            html = f.read()

        html = html.replace('<body>', f'<body style="margin:0;padding-top:50px">{overlay}')

        with open(output_file, 'w') as f:
            f.write(html)


def main():
    visualizer = EntraPrivilegeVisualizer('output/scan_results.json')
    visualizer.generate_visualization('output/privilege_graph.html')


if __name__ == "__main__":
    main()
