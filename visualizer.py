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
            subtitle=f"Tenant {self.scan.tenant_id}",
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
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        net = Network(
            height="900px", width="100%",
            bgcolor="#f8fafc", font_color="#0f172a",
            directed=True,
        )
        net.set_options("""
        {
          "physics": {
            "enabled": true,
            "barnesHut": {
              "gravitationalConstant": -20000,
              "centralGravity": 0.15,
              "springLength": 200,
              "springConstant": 0.03,
              "damping": 0.5,
              "avoidOverlap": 0.8
            },
            "solver": "barnesHut",
            "stabilization": { "enabled": true, "iterations": 1500, "fit": true }
          },
          "nodes": {
            "font": { "size": 14, "face": "-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif", "color": "#0f172a" },
            "borderWidth": 2,
            "borderWidthSelected": 5,
            "scaling": { "min": 15, "max": 80 }
          },
          "edges": {
            "smooth": { "type": "continuous" },
            "width": 2,
            "selectionWidth": 4,
            "hoverWidth": 3
          },
          "interaction": {
            "hover": true,
            "hoverConnectedEdges": true,
            "navigationButtons": true,
            "hideEdgesOnDrag": true
          }
        }
        """)

        group_role_edges = defaultdict(list)
        direct_edges = []
        pim_edges = []

        for f in self.findings:
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

        role_reach = defaultdict(int)
        for (group, role), users in group_role_edges.items():
            role_reach[role] += len(users)
        for user, role in direct_edges:
            role_reach[role] += 1
        for user, group, role in pim_edges:
            role_reach[role] += 1

        added = set()

        def add_role(name):
            if name in added:
                return
            added.add(name)
            reach = role_reach.get(name, 1)
            size = 25 + min(reach * 2, 40)
            net.add_node(name, label=name,
                         color={"background": "#ff0000", "border": "#b91c1c"},
                         font={"color": "#ffffff", "size": 16, "face": "-apple-system"},
                         shape="box",
                         size=size, title=f"Admin role: {name} ({reach} paths)")
            

        def add_group(name):
            if name in added:
                return
            added.add(name)
            net.add_node(name, label=name, color={"background": "#ffd400", "border": "#a16207"},
                         font={"color": "#0f172a", "size": 16, "face": "-apple-system", "strokeWidth": 3, "strokeColor": "#f8fafc"},
                         shape="ellipse", size=25, title=f"Group: {name}")

        def add_user(name):
            if name in added:
                return
            added.add(name)
            net.add_node(name, label=name, color={"background": "#2563eb", "border": "#1e40af"},
                         font={"color": "#ffffff"}, shape="dot",
                         size=15, title=f"User: {name}")

        # Collapsed group -> role edges
        for (group, role), users in group_role_edges.items():
            add_role(role)
            add_group(group)
            cluster_id = f"__cluster_{group}_{role}"
            if cluster_id not in added:
                added.add(cluster_id)
                title = f"{len(users)} users reach {role} via {group}:\n" + "\n".join(sorted(users)[:15])
                if len(users) > 15:
                    title += f"\n... and {len(users) - 15} more"
                net.add_node(cluster_id, label=f"{len(users)} users",
                             color={"background": "#2563eb", "border": "#1e40af"},
                             font={"color": "#ffffff"}, shape="dot", size=20, title=title)
            net.add_edge(cluster_id, group, color="#2563eb", width=2)
            net.add_edge(group, role, color="#ff0000", width=3, label=role)

        # Direct assignments
        for user, role in direct_edges:
            add_role(role)
            add_user(user)
            net.add_edge(user, role, color="#ff0000", width=2)

        # PIM eligible (dashed)
        for user, group, role in pim_edges:
            add_role(role)
            add_user(user)
            if group:
                add_group(group)
                net.add_edge(user, group, color="#ff7a00", width=2, dashes=True)
                net.add_edge(group, role, color="#ff7a00", width=2, dashes=True)
            else:
                net.add_edge(user, role, color="#ff7a00", width=2, dashes=True,
                             title="PIM eligible (dormant privilege)")

        hover_js = """
        <script type="text/javascript">
          window.addEventListener('load', function() {
            var checkNetwork = setInterval(function() {
              if (typeof network !== 'undefined' && typeof nodes !== 'undefined') {
                clearInterval(checkNetwork);
                var originalSizes = {};
                nodes.forEach(function(n) { originalSizes[n.id] = n.size || 25; });
                network.on('hoverNode', function(params) {
                  nodes.update({ id: params.node, size: originalSizes[params.node] * 5, borderWidth: 6 });
                });
                network.on('blurNode', function(params) {
                  nodes.update({ id: params.node, size: originalSizes[params.node], borderWidth: 2 });
                });
              }
            }, 100);
          });
        </script>
        """

        net.save_graph(output_file)

        with open(output_file, "r") as f:
            html = f.read()

        total = len(self.findings)
        by_sev = defaultdict(int)
        for f in self.findings:
            by_sev[f.severity] += 1

        banner = f"""
        <div style="background: #ffffff; color: #0f172a; padding: 1.25rem 1.5rem; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; border-bottom: 1px solid #e5e7eb;">
          <div style="max-width: 1400px; margin: 0 auto;">
            <div style="font-size: 1.5rem; font-weight: 700; margin: 0 0 0.25rem;">Entra ID Privilege Escalation Map</div>
            <div style="color: #64748b; font-size: 0.95rem; margin: 0 0 0.75rem;">Tenant {self.scan.tenant_id} · {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}</div>
            <div style="display: flex; gap: 2rem; padding-top: 0.75rem; border-top: 1px solid #e5e7eb;">
              <div><span style="font-size: 1.5rem; font-weight: 700;">{total}</span> <span style="color: #64748b; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em;">findings</span></div>
              <div><span style="font-size: 1.5rem; font-weight: 700; color: #ff0000;">{by_sev.get('critical', 0)}</span> <span style="color: #64748b; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em;">critical</span></div>
              <div><span style="font-size: 1.5rem; font-weight: 700; color: #ff7a00;">{by_sev.get('high', 0)}</span> <span style="color: #64748b; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em;">high</span></div>
              <div><span style="font-size: 1.5rem; font-weight: 700; color: #ffd400;">{by_sev.get('medium', 0)}</span> <span style="color: #64748b; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em;">medium</span></div>
            </div>
          </div>
        </div>
        """
        legend = """
        <div style="position: fixed; bottom: 1.5rem; right: 1.5rem; background: #ffffff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 1rem 1.25rem; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 0.85rem; color: #0f172a; box-shadow: 0 4px 12px rgba(0,0,0,0.08); z-index: 10; min-width: 260px; max-height: 85vh; overflow-y: auto;">
          <div style="font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; font-size: 0.7rem; color: #64748b; margin-bottom: 0.75rem;">Nodes</div>
          <div style="display: flex; flex-direction: column; gap: 0.5rem;">
            <div style="display: flex; align-items: center; gap: 0.625rem;">
              <span style="display: inline-block; width: 22px; height: 12px; background: #ff0000; border: 2px solid #b91c1c; border-radius: 2px;"></span>
              <span>Admin role <span style="color: #64748b;">(size = reach)</span></span>
            </div>
            <div style="display: flex; align-items: center; gap: 0.625rem;">
              <span style="display: inline-block; width: 18px; height: 12px; background: #ffd400; border: 2px solid #a16207; border-radius: 50%;"></span>
              <span>Group</span>
            </div>
            <div style="display: flex; align-items: center; gap: 0.625rem;">
              <span style="display: inline-block; width: 12px; height: 12px; background: #2563eb; border: 2px solid #1e40af; border-radius: 50%;"></span>
              <span>User</span>
            </div>
          </div>

          <div style="font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; font-size: 0.7rem; color: #64748b; margin: 1rem 0 0.75rem;">Edges</div>
          <div style="display: flex; flex-direction: column; gap: 0.5rem;">
            <div style="display: flex; align-items: center; gap: 0.625rem;">
              <span style="display: inline-block; width: 24px; height: 3px; background: #ff0000;"></span>
              <span>Active assignment</span>
            </div>
            <div style="display: flex; align-items: center; gap: 0.625rem;">
              <span style="display: inline-block; width: 24px; height: 0; border-top: 3px dashed #ff7a00;"></span>
              <span>PIM eligible (dormant)</span>
            </div>
            <div style="display: flex; align-items: center; gap: 0.625rem;">
              <span style="display: inline-block; width: 24px; height: 3px; background: #2563eb;"></span>
              <span>Group membership</span>
            </div>
          </div>

          <div style="font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; font-size: 0.7rem; color: #64748b; margin: 1rem 0 0.75rem;">Severity</div>
          <div style="display: flex; flex-direction: column; gap: 0.375rem; font-size: 0.8rem;">
            <div><span style="display: inline-block; width: 8px; height: 8px; background: #ff0000; border-radius: 50%; margin-right: 0.5rem;"></span>Critical &mdash; Tier 0 role, active</div>
            <div><span style="display: inline-block; width: 8px; height: 8px; background: #ff7a00; border-radius: 50%; margin-right: 0.5rem;"></span>High &mdash; Tier 0 dormant, Tier 1 active</div>
            <div><span style="display: inline-block; width: 8px; height: 8px; background: #ffd400; border-radius: 50%; margin-right: 0.5rem;"></span>Medium &mdash; Tier 1 dormant, Tier 2 active</div>
          </div>

          <div style="margin-top: 1rem; padding-top: 0.75rem; border-top: 1px solid #e5e7eb; font-size: 0.75rem; color: #64748b; line-height: 1.6;">
            <div><strong style="color: #0f172a;">Hover</strong> any node for details</div>
            <div><strong style="color: #0f172a;">Drag</strong> to rearrange</div>
            <div><strong style="color: #0f172a;">Scroll</strong> to zoom</div>
            <div style="margin-top: 0.5rem; font-style: italic;">"N users" nodes are collapsed group memberships. Hover to see the roster.</div>
          </div>
        </div>
        """
        html = html.replace("<body>", f"<body style='margin:0;background:#f8fafc'>{banner}")
        html = html.replace("</body>", f"{legend}{hover_js}</body>")

        with open(output_file, "w") as f:
            f.write(html)

        print(f"Graph saved to {output_file}")


def main():
    viz = EntraPrivilegeVisualizer()
    viz.generate_html_report()
    viz.generate_graph()
    print("\nBoth artifacts generated.")
    print("  Structured report: output/privilege_report.html")
    print("  Interactive graph: output/privilege_graph.html")


if __name__ == "__main__":
    main()