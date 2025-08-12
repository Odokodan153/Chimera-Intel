from flask import Flask, render_template, request, jsonify
import asyncio

# Import our new, reusable core logic function
from modules.footprint import gather_footprint_data
from modules.database import initialize_database

# Initialize the database just like in the main CLI app
initialize_database()

# Initialize the Flask application
app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    """Handles displaying the main page."""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """
    Handles the scan request from the web page's JavaScript.
    """
    domain = request.json.get('domain')
    if not domain:
        return jsonify({"error": "Domain is required."}), 400
    
    try:
        # We use asyncio.run() to execute our async function and wait for its result.
        # This is a simple way to bridge the async world with Flask's sync world.
        scan_results = asyncio.run(gather_footprint_data(domain))
        
        # We don't save to the database here, as the CLI tool is the primary
        # interface for building the historical record. The web app is for quick lookups.
        
        # Return the results as JSON to the front-end
        return jsonify(scan_results)
    except Exception as e:
        # Return any errors in a JSON format
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500


if __name__ == '__main__':
    # Run the Flask development server
    app.run(debug=True)