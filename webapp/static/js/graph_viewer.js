/**
 * Initializes the Vis.js network graph for the Chimera Intel dashboard.
 * This function reads data from the <body> tag's data-* attributes
 * to ensure the HTML <script> block remains 100% linter-friendly.
 */
export function initGraphFromDOM() {
    const body = document.body;
    const container = document.getElementById('graph-here');

    let nodes_data, edges_data;

    // 1. Read and parse the data from the DOM
    try {
        nodes_data = JSON.parse(body.dataset.nodes);
        edges_data = JSON.parse(body.dataset.edges);
    } catch (e) {
        console.error("Failed to parse graph data from DOM:", e);
        // Display a user-friendly error inside the iframe
        if (container) {
            container.innerHTML = `
                <div class"error-message" style="padding: 2rem; text-align: center; color: #e74c3c;">
                    <h2>Error loading graph</h2>
                    <p>Failed to parse graph data from template.</p>
                </div>`;
        }
        return;
    }

    // 2. Initialize the graph
    var data = {
        nodes: new vis.DataSet(nodes_data),
        edges: new vis.DataSet(edges_data)
    };
    var options = {
        nodes: {
            shape: 'dot',
            size: 16,
            font: {
                color: '#ffffff'
            }
        },
        edges: {
            width: 0.15,
            color: { inherit: 'from' },
            smooth: {
                type: 'continuous'
            },
            font: {
                color: '#ffffff',
                align: 'top'
            }
        },
        physics: {
            forceAtlas2Based: {
                gravitationalConstant: -26,
                centralGravity: 0.005,
                springLength: 230,
                springConstant: 0.18
            },
            maxVelocity: 146,
            solver: 'forceAtlas2Based',
            timestep: 0.35,
            stabilization: { iterations: 150 }
        },
        groups: {
            "Domain": { color: { background: '#F0A30A', border: '#F0A30A' }, shape: 'dot' },
            "IP": { color: { background: '#007bff', border: '#007bff' }, shape: 'dot' },
            "IPAddress": { color: { background: '#007bff', border: '#007bff' }, shape: 'dot' },
            "Person": { color: { background: '#28a745', border: '#28a745' }, shape: 'dot' },
            "PortInfo": { color: { background: '#dc3545', border: '#dc3545' }, shape: 'square' },
            "Certificate": { color: { background: '#6f42c1', border: '#6f42c1' }, shape: 'star' }
        },
        interaction: {
            tooltipDelay: 300,
            hideEdgesOnDrag: true
        }
    };
    var network = new vis.Network(container, data, options);

    // 3. Set up event listeners for context menu
    network.on("oncontext", function (params) {
        params.event.preventDefault(); // Prevent default right-click menu
        var nodeId = network.getNodeAt(params.pointer.DOM);
        
        if (nodeId) {
            var node = data.nodes.get(nodeId);
            // Send the node info to the parent window
            if (window.parent) {
                window.parent.postMessage({
                    type: 'graph-context-menu',
                    node: node,
                    event: {
                        pageX: params.event.pageX,
                        pageY: params.event.pageY
                    }
                }, '*'); // Use a specific origin in production
            }
        }
    });

    // 4. Set up click listener to close context menu
    network.on("click", function (params) {
        if (window.parent) {
            window.parent.postMessage({ type: 'graph-click' }, '*');
        }
    });
}