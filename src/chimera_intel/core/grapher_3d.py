"""
3D Interactive Knowledge Graph Generator.

Uses Plotly to generate a 3D explorable graph of entities.
"""

import typer
import json
import logging
import os
from typing import Dict, Any, List, Tuple
from .utils import console

try:
    import plotly.graph_objects as go
except ImportError:
    print("ERROR: 'plotly' library not found. Please run: pip install plotly")
    raise

logger = logging.getLogger(__name__)
graph_3d_app = typer.Typer()

def generate_3d_knowledge_graph(json_data: Dict[str, Any], output_path: str) -> None:
    """
    Generates an interactive 3D HTML knowledge graph from a JSON scan result.
    """
    logger.info(f"Generating 3D graph for {json_data.get('domain')}")
    
    nodes: Dict[str, Dict[str, Any]] = {} # id -> {label, color, size, type}
    edges: List[Tuple[str, str]] = []

    # 1. Parse Nodes and Edges
    target = json_data.get("domain") or json_data.get("company", "Unknown Target")
    nodes[target] = {"label": target, "color": "#ff4757", "size": 15, "type": "Target"}
    
    # Subdomains
    footprint_data = json_data.get("footprint", {})
    for sub_item in footprint_data.get("subdomains", {}).get("results", []):
        subdomain = sub_item.get("domain")
        if subdomain:
            nodes[subdomain] = {"label": subdomain, "color": "#1e90ff", "size": 8, "type": "Subdomain"}
            edges.append((target, subdomain))
            
    # IP Addresses
    for ip in footprint_data.get("dns_records", {}).get("A", []):
        if "Error" not in str(ip):
            nodes[ip] = {"label": ip, "color": "#feca57", "size": 10, "type": "IP Address"}
            edges.append((target, ip))

    # Technologies
    web_data = json_data.get("web_analysis", {})
    for tech_item in web_data.get("tech_stack", {}).get("results", []):
        tech = tech_item.get("technology")
        if tech:
            nodes[tech] = {"label": tech, "color": "#576574", "size": 6, "type": "Technology"}
            edges.append((target, tech))
            
    if not edges:
        logger.warning("No relationships found to graph.")
        return

    # 2. Create 3D layout (Simple spring layout for 3D)
    # A real 3D layout is complex; we'll simulate with random z-values
    # for a "spinning" effect. For a true force-directed 3D layout,
    # we'd use networkx.spring_layout(..., dim=3)
    
    import random
    import numpy as np
    
    node_ids = list(nodes.keys())
    pos = {nid: (random.random(), random.random(), random.random()) for nid in node_ids}

    # 3. Build Plotly Traces
    
    # Edges trace
    edge_x, edge_y, edge_z = [], [], []
    for edge in edges:
        x0, y0, z0 = pos[edge[0]]
        x1, y1, z1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
        edge_z.extend([z0, z1, None])

    edge_trace = go.Scatter3d(
        x=edge_x, y=edge_y, z=edge_z,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines')
        
    # Nodes trace
    node_x, node_y, node_z = [], [], []
    node_text, node_color, node_size = [], [], []
    
    for node_id in node_ids:
        x, y, z = pos[node_id]
        node_x.append(x)
        node_y.append(y)
        node_z.append(z)
        node_text.append(f"{nodes[node_id]['label']}<br>Type: {nodes[node_id]['type']}")
        node_color.append(nodes[node_id]['color'])
        node_size.append(nodes[node_id]['size'])

    node_trace = go.Scatter3d(
        x=node_x, y=node_y, z=node_z,
        mode='markers',
        hoverinfo='text',
        text=node_text,
        marker=dict(
            showscale=False,
            colorscale='Viridis',
            color=node_color,
            size=node_size,
            opacity=0.8
        ))

    # 4. Create Figure and Save
    fig = go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            title=f'3D Knowledge Graph for {target}',
            showlegend=False,
            hovermode='closest',
            margin=dict(b=0, l=0, r=0, t=40),
            scene=dict(
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, title=''),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, title=''),
                zaxis=dict(showgrid=False, zeroline=False, showticklabels=False, title=''),
                bgcolor="#111111" # Dark "Bond" theme
            )
        )
    )

    fig.write_html(output_path)
    logger.info(f"Successfully generated 3D graph at: {os.path.abspath(output_path)}")


@graph_3d_app.command("create-3d")
def create_3d_knowledge_graph(
    json_file: str = typer.Argument(..., help="Path to the JSON scan result file."),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Path to save the HTML graph."
    ),
):
    """(NEW) Creates an interactive 3D knowledge graph from a JSON file."""
    logger.info("Generating 3D knowledge graph from: %s", json_file)

    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Error reading file '{json_file}': {e}")
        raise typer.Exit(code=1)

    if not output_file:
        target_name = data.get("domain") or data.get("company", "graph_3d")
        output_path = f"{target_name.replace('.', '_')}_graph_3d.html"
    else:
        output_path = output_file
        
    generate_3d_knowledge_graph(data, output_path)
    console.print(f"[green]3D Graph saved to {output_path}[/green]")