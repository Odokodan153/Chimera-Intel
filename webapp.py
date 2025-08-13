from flask import Flask, render_template, request, jsonify, url_for
import asyncio
import os

# Import the necessary functions from our modules
from modules.footprint import gather_footprint_data
from modules.database import initialize_database
from modules.grapher import generate_knowledge_graph

# Initialize the database just like in the main CLI app
initialize_database()

# Initialize the Flask application
app = Flask(__name__)

# Ensure the directory for static/graphs exists so we can save graph files there.
# This prevents errors if the folder hasn't been created yet.
os.makedirs(os.path.join('static', 'graphs'), exist_ok=True)

@app.route('/', methods=['GET'])
def index():
    """Handles displaying the main page by rendering the HTML template."""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """
    Handles the asynchronous scan request from the web page's JavaScript.
    """
    domain = request.json.get('domain')
    if not domain:
        return jsonify({"error": "Domain is required."}), 400
    
    try:
        # We use asyncio.run() to execute our async core logic function and wait for its result.
        scan_results = asyncio.run(gather_footprint_data(domain))
        
        # After a successful scan, generate a corresponding knowledge graph
        graph_filename = f"{domain.replace('.', '_')}_graph.html"
        graph_filepath = os.path.join('static', 'graphs', graph_filename)
        generate_knowledge_graph(scan_results, graph_filepath)
        
        # Add the publicly accessible URL for the graph to the results dictionary.
        # The frontend JavaScript will use this URL to create a "View Graph" link.
        scan_results['graph_url'] = url_for('static', filename=f'graphs/{graph_filename}')
        
        # Return the complete results (including the new graph URL) as JSON to the frontend
        return jsonify(scan_results)
    except Exception as e:
        # Return any errors in a JSON format so the frontend can display them
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500

if __name__ == '__main__':
    # Run the Flask development server.
    # debug=True enables features like auto-reloading when you save code changes.
    app.run(debug=True)