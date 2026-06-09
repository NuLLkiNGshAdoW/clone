"""Topology visualization using networkx + matplotlib.

Provides draw_topology(ax, arp_table, blocked_ips, alerts) which plots a radial
layout with gateway center and devices around it. Nodes with recent alerts are
highlighted in red.
"""
from typing import Dict, Set, List
import networkx as nx


def draw_topology(ax, arp_table: Dict[str, str], blocked_ips: Set[str], alerts: List[dict]):
    # simple radial layout using networkx; fallback if networkx missing
    try:
        G = nx.Graph()
        gateway = "GATEWAY"
        G.add_node(gateway)
        for ip, mac in arp_table.items():
            G.add_node(ip)
            G.add_edge(gateway, ip)
        pos = nx.spring_layout(G, seed=42)
        ax.clear(); ax.set_facecolor('#0A0F1E'); ax.axis('off')
        # draw edges
        nx.draw_networkx_edges(G, pos, ax=ax, edge_color='#1A2A4A')
        # node colors
        alert_ips = {a['actor'] for a in alerts}
        colors = [('#FF3B5C' if n in alert_ips or n in blocked_ips else '#00FF88') for n in G.nodes()]
        nx.draw_networkx_nodes(G, pos, ax=ax, node_color=colors, node_size=220)
        nx.draw_networkx_labels(G, pos, ax=ax, font_size=7, font_color='#E8F4FD')
    except Exception as e:
        # when networkx isn't available or fails, fallback to simple plotting
        import math
        ax.clear(); ax.set_facecolor('#0A0F1E'); ax.axis('off')
        ips = list(arp_table.keys())[:24]
        if not ips:
            ax.text(0.5,0.5,'Waiting for ARP traffic…',ha='center',va='center',
                    color='#4A6FA5',fontsize=14,transform=ax.transAxes)
            return
        n = len(ips); cx,cy,r = 0.5,0.5,0.38
        ax.scatter([cx],[cy],s=500,color='#00D4FF',zorder=5,marker='D')
        ax.text(cx,cy-0.08,'GATEWAY',ha='center',color='#00D4FF',
                 fontsize=9,fontweight='bold')
        for i,ip in enumerate(ips):
            angle = 2*math.pi*i/n; x = cx+r*math.cos(angle); y = cy+r*math.sin(angle)
            c = '#FF3B5C' if ip in blocked_ips else '#00FF88'
            ax.plot([cx,x],[cy,y],color='#1A2A4A',lw=0.8,zorder=1)
            ax.scatter([x],[y],s=220,color=c,zorder=4,alpha=0.9)
            ax.text(x,y-0.06,ip,ha='center',color=c,fontsize=7)
