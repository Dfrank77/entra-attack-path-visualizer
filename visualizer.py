"""Read findings from shared storage and produce two artifacts:
1. Structured HTML report (via shared library)
2. Interactive pyvis graph (privilege escalation map)
"""

import os
from collections import defaultdict
from datetime import datetime
from pyvis.network import Network

from entra_security_report import Storage, render


class EntraPrivilegeVisualizer:
    def __init__(self):
        self.storage = Storage(".findings")
        latest_scan = self.storage.latest_scan(tool="attack-path")
        if not latest_scan:
            raise SystemExit("No attack-path scans found. Run entra_scanner.py first.")

        self.findings = [
            self.storage.load_finding(fid)
            for fid in latest_scan.finding_ids
        ]
        self.findings = [f for f in self.findings if f is not None]
        self.scan = latest_scan

    def generate_html_report(self, output_file="output/privilege_report.html"):
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        active_count = sum(1 for f in self.findings if f.evidence.get("assignment_type") == "active")
        eligible_count = sum(1 for f in self.findings if f.evidence.get("assignment_type") == "eligible")

        html = render(
            self.findings,
            title="Entra ID Privilege Escalation Map",
            subtitle=f"Tenant ...{self.scan.tenant_id.split('-')[-1]}",
            tenant_id=self.scan.tenant_id,
            group_by="subject",
            metadata={
                "users at risk": len({f.subject.id for f in self.findings}),
                "active paths": active_count,
                "pim eligible": eligible_count,
            },
        )

        with open(output_file, "w") as f:
            f.write(html)
        print(f"HTML report saved to {output_file}")

    def generate_graph(self, output_file="output/privilege_graph.html"):
        """Interactive pyvis graph of privilege escalation paths.
        Filtered to critical + high severity only for readability."""
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        # Filter: only critical and high in the graph. Medium stays in the report.
        graph_findings = [f for f in self.findings if f.severity in ("critical", "high")]

        net = Network(
            height="900px", width="100%",
            bgcolor="#0d1117", font_color="#e6edf3",
            directed=True,
        )
        net.set_options("""
        {
          "layout": {
            "hierarchical": {
              "enabled": true,
              "direction": "UD",
              "sortMethod": "directed",
              "levelSeparation": 180,
              "nodeSpacing": 140,
              "treeSpacing": 200,
              "blockShifting": true,
              "edgeMinimization": true,
              "parentCentralization": true
            }
          },
          "physics": {
            "enabled": true,
            "hierarchicalRepulsion": {
              "centralGravity": 0.0,
              "springLength": 150,
              "springConstant": 0.02,
              "nodeDistance": 140,
              "damping": 0.4
            },
            "solver": "hierarchicalRepulsion",
            "stabilization": { "enabled": true, "iterations": 400, "fit": true }
          },
          "nodes": { "font": { "size": 14, "face": "-apple-system, BlinkMacSystemFont, sans-serif" }, "borderWidth": 2 },
          "edges": { "smooth": { "type": "cubicBezier", "forceDirection": "vertical", "roundness": 0.4 } },
          "interaction": { "hover": true, "navigationButtons": true, "hideEdgesOnDrag": true, "zoomView": true }
        }
        """)

        legend = """
        <div style="position: absolute; bottom: 20px; right: 20px; background: rgba(13, 17, 23, 0.95); border: 1px solid #30363d; border-radius: 8px; padding: 1rem 1.25rem; font-family: -apple-system, sans-serif; color: #e6edf3; font-size: 0.85rem; z-index: 10;">
          <div style="font-weight: 700; color: #7d8590; font-size: 0.7rem; letter-spacing: 0.05em; margin-bottom: 0.5rem;">NODES</div>
          <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem;">
            <div style="width: 24px; height: 12px; background: #f85149; border: 2px solid #f85149;"></div>
            <span>Admin role (size = reach)</span>
          </div>
          <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem;">
            <div style="width: 20px; height: 12px; background: #d29922; border-radius: 50%;"></div>
            <span>Group</span>
          </div>
          <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.75rem;">
            <div style="width: 12px; height: 12px; background: #58a6ff; border-radius: 50%;"></div>
            <span>User</span>
          </div>
          <div style="font-weight: 700; color: #7d8590; font-size: 0.7rem; letter-spacing: 0.05em; margin-bottom: 0.5rem;">EDGES</div>
          <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem;">
            <div style="width: 24px; height: 2px; background: #f85149;"></div>
            <span>Active assignment</span>
          </div>
          <div style="display: flex; align-items: center; gap: 0.5rem;">
            <div style="width: 24px; border-top: 2px dashed #d29922;"></div>
            <span>PIM eligible (dormant)</span>
          </div>
        </div>
        """
        

        # Collapse group-based paths so we don't draw 50 lines to the same role node
        group_role_edges = defaultdict(list)
        direct_edges = []
        pim_edges = []

        for f in graph_findings:
            path = f.evidence.get("path", [])
            path_type = f.evidence.get("path_type", "")
            if len(path) == 3:
                key = (path[1], path[2])
                if path_type.startswith("pim"):
                    pim_edges.append((f.subject.display_name, path[1], path[2]))
                else:
                    group_role_edges[key].append(f.subject.display_name)
            elif len(path) == 2:
                if path_type.startswith("pim"):
                    pim_edges.append((f.subject.display_name, None, path[1]))
                else:
                    direct_edges.append((f.subject.display_name, path[1]))

        added = set()

        def add_role(name, reach=1):
            if name in added:
                return
            added.add(name)
            size = min(20 + reach * 3, 60)
            net.add_node(name, label=name, color="#f85149", shape="box",
                         size=size, level=0, title=f"Admin role: {name}\nReach: {reach} users")

        def add_group(name):
            if name in added:
                return
            added.add(name)
            net.add_node(name, label=name, color="#d29922", shape="ellipse",
                         size=25, level=1, title=f"Group: {name}")

        def add_user(name):
            if name in added:
                return
            added.add(name)
            net.add_node(name, label=name, color="#58a6ff", shape="dot",
                         size=12, level=2, title=f"User: {name}")

        # Compute role reach for sizing
        role_reach = defaultdict(int)
        for (_, role), users in group_role_edges.items():
            role_reach[role] += len(users)
        for _, role in direct_edges:
            role_reach[role] += 1
        for _, _, role in pim_edges:
            role_reach[role] += 1

        # Collapsed group -> role edges
        for (group, role), users in group_role_edges.items():
            add_role(role, reach=role_reach[role])
            add_group(group)
            cluster_id = f"__cluster_{group}_{role}"
            if cluster_id not in added:
                added.add(cluster_id)
                title = f"{len(users)} users reach {role} via {group}:\n" + "\n".join(sorted(users)[:15])
                if len(users) > 15:
                    title += f"\n... and {len(users) - 15} more"
                net.add_node(cluster_id, label=f"{len(users)} users",
                             color="#58a6ff", shape="dot", size=18, level=2, title=title)
            net.add_edge(cluster_id, group, color="#58a6ff", width=2)
            net.add_edge(group, role, color="#f85149", width=3, label=role)

        # Direct assignments
        for user, role in direct_edges:
            add_role(role, reach=role_reach[role])
            add_user(user)
            net.add_edge(user, role, color="#f85149", width=2)

        # PIM eligible (dashed)
        for user, group, role in pim_edges:
            add_role(role, reach=role_reach[role])
            add_user(user)
            if group:
                add_group(group)
                net.add_edge(user, group, color="#d29922", width=2, dashes=True)
                net.add_edge(group, role, color="#d29922", width=2, dashes=True)
            else:
                net.add_edge(user, role, color="#d29922", width=2, dashes=True,
                             title="PIM eligible (dormant privilege)")

        net.save_graph(output_file)

        # Inject a header banner above the pyvis output
        with open(output_file, "r") as f:
            html = f.read()

        total = len(self.findings)
        graph_total = len(graph_findings)
        by_sev = defaultdict(int)
        for f in self.findings:
            by_sev[f.severity] += 1

        banner = f"""
        <div style="background: #0d1117; color: #e6edf3; padding: 1rem 2rem; font-family: -apple-system, BlinkMacSystemFont, sans-serif; border-bottom: 1px solid #30363d;">
          <div style="display: flex; gap: 3rem; align-items: baseline;">
            <div>
              <div style="font-size: 1.25rem; font-weight: 700;">Entra ID Privilege Escalation Map</div>
              <div style="color: #7d8590; font-size: 0.85rem; margin-top: 0.25rem;">
                Tenant ...{self.scan.tenant_id.split('-')[-1]} · {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}
              </div>
            </div>
            <div style="margin-left: auto; display: flex; gap: 2rem; align-items: baseline;">
              <div><span style="color: #f85149; font-weight: 700; font-size: 1.5rem;">{by_sev.get('critical', 0)}</span> <span style="color: #7d8590; font-size: 0.85rem;">CRITICAL</span></div>
              <div><span style="color: #ea580c; font-weight: 700; font-size: 1.5rem;">{by_sev.get('high', 0)}</span> <span style="color: #7d8590; font-size: 0.85rem;">HIGH</span></div>
              <div><span style="color: #eab308; font-weight: 700; font-size: 1.5rem;">{by_sev.get('medium', 0)}</span> <span style="color: #7d8590; font-size: 0.85rem;">MEDIUM</span></div>
              <div><span style="font-weight: 700; font-size: 1.5rem;">{total}</span> <span style="color: #7d8590; font-size: 0.85rem;">TOTAL</span></div>
            </div>
          </div>
          <div style="color: #7d8590; font-size: 0.85rem; margin-top: 0.5rem;">
            Graph shows {graph_total} critical + high findings. Medium ({by_sev.get('medium', 0)}) in the structured report only.
          </div>
        </div>
        """
        html = html.replace("<body>", f"<body>{banner}")
        html = html.replace("</body>", f"{legend}</body>")

        with open(output_file, "w") as f:
            f.write(html)

        print(f"Graph saved to {output_file}")


def main():
    viz = EntraPrivilegeVisualizer()
    viz.generate_html_report()
  #  viz.generate_graph()
    print("\nBoth artifacts generated.")
    print("  Structured report: output/privilege_report.html")
    print("  Interactive graph: output/privilege_graph.html")


if __name__ == "__main__":
    main()