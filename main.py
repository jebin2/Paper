from flask import Flask, request, jsonify, send_from_directory, abort
from flask_cors import CORS
import os
import glob
import re
import base64
import time
import tempfile
import logging

# --- LOGGING SETUP ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# --- CORS SETUP ---
# Enable CORS for all routes (configurable via environment)
CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*')  # '*' allows all, or comma-separated origins
CORS(app, origins=CORS_ORIGINS.split(',') if CORS_ORIGINS != '*' else '*')

# --- CONFIGURATION (Environment Variables with Defaults) ---
DATA_DIR = os.environ.get('DATA_DIR', '/tmp')
MAX_TOTAL_SIZE_MB = int(os.environ.get('MAX_TOTAL_SIZE_MB', 100))
PURGE_TO_SIZE_MB = int(os.environ.get('PURGE_TO_SIZE_MB', 80))
AGE_LIMIT_DAYS = int(os.environ.get('AGE_LIMIT_DAYS', 2))
MAX_CONTENT_SIZE_MB = int(os.environ.get('MAX_CONTENT_SIZE_MB', 10))

# Directory for static files (index.html, etc.)
STATIC_DIR = os.environ.get('STATIC_DIR', os.path.dirname(os.path.abspath(__file__)))

# Limit request payload size (prevents large uploads from consuming memory)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

# --- SECURITY HELPER ---
def sanitize_hash(hash_string):
    """
    Validates that the hash is a 16-character hexadecimal string.
    This is CRITICAL to prevent path traversal attacks.
    """
    if not isinstance(hash_string, str):
        return False
    # Check for length and character set
    return bool(re.match(r'^[0-9a-f]{16}$', hash_string))

# --- FILE MANAGEMENT ---
def cleanup_files():
    """
    Remove old files based on two conditions:
    1. Any file older than AGE_LIMIT_DAYS is removed.
    2. If total size still exceeds MAX_TOTAL_SIZE_MB, the oldest remaining files are removed
       until the total size is below PURGE_TO_SIZE_MB.
    """
    try:
        content_files = glob.glob(os.path.join(DATA_DIR, '*_content.txt'))
        if not content_files:
            return

        now = time.time()
        age_limit_seconds = AGE_LIMIT_DAYS * 24 * 60 * 60
        age_threshold = now - age_limit_seconds
        
        all_file_info = []
        for f_path in content_files:
            try:
                mtime = os.path.getmtime(f_path)
                size = os.path.getsize(f_path)
                all_file_info.append({'path': f_path, 'size': size, 'mtime': mtime})
            except OSError:
                continue
        
        # --- Stage 1: Identify files to delete by age ---
        files_to_keep = []
        files_to_delete = []
        
        for f_info in all_file_info:
            if f_info['mtime'] < age_threshold:
                files_to_delete.append(f_info)
            else:
                files_to_keep.append(f_info)
        
        # --- Stage 2: Identify files to delete by size from the remaining pool ---
        current_size_of_kept_files = sum(f['size'] for f in files_to_keep)
        max_size_bytes = MAX_TOTAL_SIZE_MB * 1024 * 1024
        
        if current_size_of_kept_files > max_size_bytes:
            # Sort the files we were planning to keep by age (oldest first)
            files_to_keep.sort(key=lambda x: x['mtime'])
            
            target_size_bytes = PURGE_TO_SIZE_MB * 1024 * 1024
            
            # Move oldest files from 'keep' to 'delete' until size is acceptable
            while current_size_of_kept_files > target_size_bytes and files_to_keep:
                file_to_move = files_to_keep.pop(0) # Oldest is at the front
                files_to_delete.append(file_to_move)
                current_size_of_kept_files -= file_to_move['size']

        # --- Stage 3: Perform the actual deletion ---
        if not files_to_delete:
            return

        logger.info(f"Cleanup: Deleting {len(files_to_delete)} old/oversized file(s).")
        for f_info in files_to_delete:
            try:
                content_path = f_info['path']
                salt_path = content_path.replace('_content.txt', '_salt.txt')
                
                os.remove(content_path)
                if os.path.exists(salt_path):
                    os.remove(salt_path)
            except OSError as e:
                logger.error(f"Cleanup: Error removing file {f_info['path']}: {e}")

    except Exception as e:
        logger.error(f"Error during file cleanup: {e}")

# --- FLASK ROUTES ---
@app.route('/')
def index():
    return send_from_directory(STATIC_DIR, 'index.html')

@app.route('/health')
def health():
    """Health check endpoint for monitoring."""
    return jsonify({'status': 'ok'})

@app.route('/api/load', methods=['POST'])
def load_content():
    data = request.json
    if not data:
        return jsonify({'error': 'Invalid JSON payload'}), 400
    file_hash = data.get('hash', '')

    # CRITICAL: Sanitize input to prevent path traversal
    if not sanitize_hash(file_hash):
        return jsonify({'error': 'Invalid hash format'}), 400

    content_path = os.path.join(DATA_DIR, f'{file_hash}_content.txt')
    salt_path = os.path.join(DATA_DIR, f'{file_hash}_salt.txt')
    
    try:
        # Handle the salt first. If it doesn't exist, this is a new note.
        if os.path.exists(salt_path):
            with open(salt_path, 'r', encoding='utf-8') as f:
                salt_b64 = f.read()
        else:
            # New note: generate a new, cryptographically secure salt
            salt_bytes = os.urandom(16)
            salt_b64 = base64.b64encode(salt_bytes).decode('utf-8')
            # Save the new salt atomically to prevent race conditions
            try:
                fd, tmp_path = tempfile.mkstemp(dir=DATA_DIR, suffix='.tmp')
                os.write(fd, salt_b64.encode('utf-8'))
                os.close(fd)
                os.rename(tmp_path, salt_path)  # Atomic on POSIX
            except OSError:
                # If atomic write fails, fall back to direct write
                with open(salt_path, 'w', encoding='utf-8') as f:
                    f.write(salt_b64)

        # Now, handle the content. It might not exist yet for a new note.
        if os.path.exists(content_path):
            with open(content_path, 'r', encoding='utf-8') as f:
                encrypted_content = f.read()
        else:
            encrypted_content = ''
        
        return jsonify({'content': encrypted_content, 'salt': salt_b64})
    except Exception as e:
        logger.error(f"Error during load: {e}")
        return jsonify({'error': 'Failed to load content from server'}), 500

@app.route('/api/save', methods=['POST'])
def save_content():
    data = request.json
    if not data:
        return jsonify({'error': 'Invalid JSON payload'}), 400
    file_hash = data.get('hash', '')
    encrypted_content = data.get('content', '')

    # CRITICAL: Sanitize input to prevent path traversal
    if not sanitize_hash(file_hash):
        return jsonify({'error': 'Invalid hash format'}), 400
    
    # The client must provide content to save
    if not isinstance(encrypted_content, str):
        return jsonify({'error': 'Invalid content format'}), 400
    
    # Validate content size to prevent abuse
    max_content_bytes = MAX_CONTENT_SIZE_MB * 1024 * 1024
    if len(encrypted_content.encode('utf-8')) > max_content_bytes:
        return jsonify({'error': f'Content too large. Maximum size is {MAX_CONTENT_SIZE_MB}MB'}), 413

    content_path = os.path.join(DATA_DIR, f'{file_hash}_content.txt')
    
    try:
        # Save encrypted content directly
        with open(content_path, 'w', encoding='utf-8') as f:
            f.write(encrypted_content)
        
        # Run cleanup routine after a successful save
        cleanup_files()
        
        return jsonify({'status': 'saved'})
    except Exception as e:
        logger.error(f"Error during save: {e}")
        return jsonify({'error': 'Save failed on server'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7860, debug=False)