from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO
import threading
import logging
from logging.handlers import QueueHandler
import queue
import time
import os
from main import run_sitemap_generation

app = Flask(__name__)
app.config['SECRET_KEY'] = 'development-key'  # Safe for development and GitHub sharing; for production, use a secure key via environment variable
socketio = SocketIO(app)

# Logging setup
log_queue = queue.Queue()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
queue_handler = QueueHandler(log_queue)
queue_handler.setFormatter(formatter)
logger.handlers = [queue_handler]  # Replace default handlers

# Global state
generation_thread = None
is_generating = False
progress = {
    'subdomains_found': 0,
    'urls_crawled': 0,
    'total_subdomains': 0,
    'start_time': None
}

class SocketIOHandler(logging.Handler):
    """Custom logging handler to emit logs to SocketIO."""
    def emit(self, record):
        msg = self.format(record)
        socketio.emit('log', {'message': msg})

def process_log_queue():
    """Process log messages from the queue and emit to SocketIO."""
    while True:
        try:
            record = log_queue.get_nowait()
            for handler in logger.handlers:
                if isinstance(handler, SocketIOHandler):
                    handler.emit(record)
        except queue.Empty:
            break
        socketio.sleep(0.1)
    socketio.start_background_task(process_log_queue)

@app.route('/')
def index():
    """Serve the React frontend."""
    return render_template('index.html')

@app.route('/start', methods=['POST'])
def start_generation():
    """Start sitemap generation."""
    global generation_thread, is_generating, progress
    if is_generating:
        return jsonify({'error': 'Generation already in progress'}), 400

    data = request.json
    tld = data.get('tld', '').strip()
    api_token = data.get('api_token', '').strip()
    respect_robots = data.get('respect_robots', True)
    timeout_input = data.get('timeout', '5').strip()

    try:
        timeout = float(timeout_input) if timeout_input else 5
        if timeout <= 0:
            raise ValueError("Timeout must be positive")
    except ValueError as e:
        logger.warning(f"Invalid timeout input: {e}. Using default timeout of 5 seconds.")
        timeout = 5

    # Reset progress
    progress = {
        'subdomains_found': 0,
        'urls_crawled': 0,
        'total_subdomains': 0,
        'start_time': time.time()
    }

    def run_and_reset():
        global is_generating
        try:
            run_sitemap_generation(tld, api_token, respect_robots, timeout, logger, progress)
        finally:
            is_generating = False  # Reset flag after completion or error
            logger.info("Sitemap generation completed or terminated")

    is_generating = True
    generation_thread = threading.Thread(target=run_and_reset)
    generation_thread.daemon = True
    generation_thread.start()

    return jsonify({'status': 'Generation started'})

@app.route('/status')
def status():
    """Check if generation is in progress."""
    return jsonify({'is_generating': is_generating})

@app.route('/progress')
def get_progress():
    """Return progress and estimated time remaining."""
    if not is_generating:
        return jsonify({'subdomains_found': 0, 'urls_crawled': 0, 'estimated_time': 0})

    # Estimate time: 2.5 seconds per subdomain/URL
    items_processed = progress['subdomains_found'] + progress['urls_crawled']
    items_total = max(progress['total_subdomains'], progress['subdomains_found'])
    if items_total == 0:
        items_total = 17  # Fallback based on your log (17 unique pages)
    time_per_item = 2.5
    estimated_total_time = items_total * time_per_item
    elapsed_time = time.time() - progress['start_time']
    estimated_remaining = max(0, estimated_total_time - elapsed_time)

    return jsonify({
        'subdomains_found': progress['subdomains_found'],
        'urls_crawled': progress['urls_crawled'],
        'estimated_time': round(estimated_remaining)
    })

@app.route('/download')
def download_sitemap():
    """Serve the generated sitemap.xml for download."""
    sitemap_path = 'sitemap.xml'
    if os.path.exists(sitemap_path):
        return send_file(sitemap_path, as_attachment=True, download_name='sitemap.xml')
    else:
        logger.error("Sitemap file not found")
        return jsonify({'error': 'Sitemap file not found'}), 404

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection."""
    logger.handlers.append(SocketIOHandler())  # Add SocketIO handler on connect
    logger.info("Client connected")
    socketio.start_background_task(process_log_queue)

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection."""
    logger.info("Client disconnected")
    # Remove SocketIO handler to prevent memory leaks
    logger.handlers = [h for h in logger.handlers if not isinstance(h, SocketIOHandler)]

def run_webui(port=5000):
    """Run the Flask-SocketIO server on the specified port."""
    socketio.run(app, host='0.0.0.0', port=port)

if __name__ == "__main__":
    run_webui()
