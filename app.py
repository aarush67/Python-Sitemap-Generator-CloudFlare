import os
import time
import logging
import queue
from threading import Thread
from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit
from multiprocessing import Process, Manager, Queue, set_start_method
try:
    from main import run_sitemap_generation as generate_sitemap
except ImportError:
    raise ImportError("Could not import generate_sitemap from main module")

# Set template folder explicitly
template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
app = Flask(__name__, template_folder=template_dir)
app.config['SECRET_KEY'] = os.urandom(24).hex()  # Secure session handling
socketio = SocketIO(app, cors_allowed_origins="*")

# Setup logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger('sitemap')
file_handler = logging.FileHandler('sitemap.log')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

# Queue for logs from child processes
log_queue = Queue()

# Custom handler to put logs into queue
class QueueHandler(logging.Handler):
    def __init__(self, queue):
        super().__init__()
        self.queue = queue

    def emit(self, record):
        try:
            msg = self.format(record)
            self.queue.put(msg)
        except Exception:
            pass

queue_handler = QueueHandler(log_queue)
queue_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(queue_handler)

# Background thread to process log queue and emit to socket.io
def log_processor():
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    while True:
        try:
            msg = log_queue.get(timeout=1)
            # Ensure msg is a string
            if isinstance(msg, logging.LogRecord):
                msg = formatter.format(msg)
            logger.debug(f"Emitting log: {msg}")
            socketio.emit('log', {'message': msg})
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Log processor error: {str(e)}", exc_info=True)

log_thread = Thread(target=log_processor, daemon=True)
log_thread.start()

# Global process tracking
manager = Manager()
progress = manager.dict({
    'subdomains_found': 0,
    'urls_crawled': 0,
    'total_subdomains': 0,
    'start_time': 0,
    'status': 'idle',
    'error_message': '',
    'is_generating': False
})
progress_lock = manager.Lock()
active_process = None
estimated_urls_per_subdomain = 10  # Adjust based on typical site size

@app.route('/')
def index():
    try:
        logger.info(f"Attempting to render template from: {app.template_folder}")
        if not os.path.exists(os.path.join(app.template_folder, 'index.html')):
            logger.error(f"Template file not found: {os.path.join(app.template_folder, 'index.html')}")
            return jsonify({'error': 'Template file not found'}), 500
        return render_template('index.html')
    except Exception as e:
        logger.error(f"Error rendering index.html: {str(e)}", exc_info=True)
        return jsonify({'error': f'Template rendering failed: {str(e)}'}), 500

@app.route('/start', methods=['POST'])
def start_crawl():
    global active_process

    if active_process is not None and active_process.is_alive():
        logger.warning("Crawling already in progress")
        return jsonify({'status': 'Crawling already in progress'}), 400

    try:
        data = request.get_json()
        if not data or 'tld' not in data:
            logger.error("Domain is required")
            return jsonify({'error': 'Domain is required'}), 400

        tld = data['tld'].strip()
        if not tld:
            logger.error("Invalid domain")
            return jsonify({'error': 'Invalid domain'}), 400

        api_token = data.get('api_token', '').strip()
        respect_robots = data.get('respect_robots', True)
        timeout = float(data.get('timeout', 5))
        use_multithreading = data.get('use_multithreading', False)
        max_workers = data.get('max_workers', '4')
        if max_workers == 'auto':
            max_workers = os.cpu_count() or 4
        else:
            max_workers = int(max_workers)
        max_depth = int(data.get('max_depth', 5))
        output_file = data.get('output_file', 'sitemap.xml')
        include_subdomains = data.get('include_subdomains', '').split(',') if data.get('include_subdomains') else None
        exclude_subdomains = data.get('exclude_subdomains', '').split(',') if data.get('exclude_subdomains') else None
        rate_limit = float(data.get('rate_limit', 1.0))

        # Reset progress
        with progress_lock:
            progress.update({
                'subdomains_found': 0,
                'urls_crawled': 0,
                'total_subdomains': 0,
                'start_time': time.time(),
                'status': 'running',
                'error_message': '',
                'is_generating': True
            })

        # Start new process
        logger.info(f"Starting crawl for {tld} with multiprocessing: {use_multithreading}, workers: {max_workers}")
        active_process = Process(
            target=generate_sitemap,
            args=(
                tld, api_token, respect_robots, timeout, log_queue, progress, progress_lock,
                use_multithreading, max_workers, max_depth, output_file,
                include_subdomains, exclude_subdomains, rate_limit
            )
        )
        active_process.start()

        return jsonify({'status': 'Started crawling'})

    except Exception as e:
        logger.error(f"Crawl start failed: {str(e)}", exc_info=True)
        with progress_lock:
            progress['status'] = 'error'
            progress['error_message'] = str(e)
            progress['is_generating'] = False
        return jsonify({'error': 'Failed to start crawl', 'message': str(e)}), 500

@app.route('/status', methods=['GET'])
def status():
    try:
        with progress_lock:
            status_data = dict(progress)
            # Check if process has exited unexpectedly
            if active_process is not None and not active_process.is_alive() and status_data['is_generating']:
                logger.error("Crawl process terminated unexpectedly")
                status_data['status'] = 'error'
                status_data['error_message'] = 'Crawl process terminated unexpectedly'
                status_data['is_generating'] = False
                progress.update(status_data)
            return jsonify(status_data)
    except Exception as e:
        logger.error(f"Status check failed: {str(e)}", exc_info=True)
        return jsonify({'error': 'Status check failed'}), 500

@app.route('/progress', methods=['GET'])
def progress_status():
    try:
        with progress_lock:
            estimated_time = 0
            if progress['total_subdomains'] > 0:
                remaining_subdomains = progress['total_subdomains'] - progress['subdomains_found']
                remaining_urls = estimated_urls_per_subdomain * remaining_subdomains
                time_per_url = 1.0  # Assume 1 second per URL (adjust based on rate_limit)
                estimated_time = int(remaining_urls * time_per_url)
            return jsonify({'estimated_time': estimated_time})
    except Exception as e:
        logger.error(f"Progress check failed: {str(e)}", exc_info=True)
        return jsonify({'error': 'Progress check failed'}), 500

@app.route('/download', methods=['GET'])
def download_sitemap():
    try:
        output_file = request.args.get('output_file', 'sitemap.xml')
        if not os.path.exists(output_file):
            logger.error(f"Sitemap file not found: {output_file}")
            return jsonify({'error': 'Sitemap file not found'}), 404
        return send_file(output_file, as_attachment=True)
    except Exception as e:
        logger.error(f"Download failed: {str(e)}", exc_info=True)
        return jsonify({'error': 'Download failed', 'message': str(e)}), 500

@socketio.on('connect')
def handle_connect():
    try:
        emit('connected', {'message': 'Connected to server'})
        logger.info("Client connected via WebSocket")
    except Exception as e:
        logger.error(f"WebSocket connect failed: {str(e)}", exc_info=True)

@socketio.on('disconnect')
def handle_disconnect():
    logger.info("Client disconnected from WebSocket")

@socketio.on('get_status')
def handle_status():
    try:
        with progress_lock:
            emit('status', dict(progress))
    except Exception as e:
        logger.error(f"WebSocket status update failed: {str(e)}", exc_info=True)

def run_webui(port=5000):
    """Run the Flask-SocketIO web server."""
    try:
        logger.info(f"Starting WebUI on port {port}")
        socketio.run(app, host='0.0.0.0', port=port, debug=False, use_reloader=False)
    except Exception as e:
        logger.error(f"WebUI failed: {str(e)}", exc_info=True)
        raise

def cleanup():
    """Clean up resources before shutdown."""
    global active_process
    try:
        if active_process and active_process.is_alive():
            logger.info("Terminating active crawl process")
            active_process.terminate()
            active_process.join(timeout=2.0)
            if active_process.is_alive():
                logger.warning("Process did not terminate gracefully")
        logger.info("Cleaned up resources")
    except Exception as e:
        logger.error(f"Cleanup failed: {str(e)}", exc_info=True)

if __name__ == '__main__':
    try:
        set_start_method('spawn', force=True)
        # Register cleanup on exit
        import atexit
        atexit.register(cleanup)
        
        # Start the web UI
        web_thread = Thread(target=run_webui, daemon=True)
        web_thread.start()
        web_thread.join()
        
    except KeyboardInterrupt:
        logger.info("Shutting down server")
        cleanup()
    except Exception as e:
        logger.error(f"Startup failed: {str(e)}", exc_info=True)
        cleanup()
        raise
