"""
Shadow Cipher Vault - Secure File Storage System
Developed by KIRCATCRACKER
A Flask-based application for encrypted file storage with RSA authentication.
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import json
import datetime
import re
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import secrets
import jwt
from functools import wraps
import docker
import tarfile
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vault.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    public_key = db.Column(db.Text, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    files = db.relationship('File', backref='owner', lazy=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    encrypted_data = db.Column(db.Text, nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class SecurityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Admin access required', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def validate_password_strength(password):
    """
    Validate password strength requirements
    Returns: (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*]', password):
        return False, "Password must contain at least one special character (!@#$%^&*)"
    
    return True, "Password meets all requirements"

def log_security_action(action, details=None):
    log = SecurityLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        action=action,
        details=details,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        key_file = data.get('key_file')
        
        user = User.query.filter_by(email=email).first()
        if user and user.public_key:
            try:
                # In a real implementation, you would verify the RSA signature
                # For demo purposes, we'll just check if the user exists
                login_user(user)
                log_security_action('LOGIN_SUCCESS', f'User {user.username} logged in with email {email}')
                return jsonify({'success': True, 'redirect': url_for('dashboard')})
            except Exception as e:
                log_security_action('LOGIN_FAILED', f'Failed login attempt for email {email}')
                return jsonify({'success': False, 'error': 'Invalid credentials'})
        else:
            log_security_action('LOGIN_FAILED', f'Failed login attempt for email {email}')
            return jsonify({'success': False, 'error': 'Invalid credentials'})
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        public_key = data.get('public_key')
        # Validate password strength
        is_valid_password, password_error = validate_password_strength(password)
        if not is_valid_password:
            return jsonify({'success': False, 'error': password_error})
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'error': 'Username already exists'})
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'error': 'Email already registered'})
        # Docker: create volume and container for user
        container_name = f'user_{username}_container'
        volume_name = f'user_{username}_volume'
        try:
            client = docker.from_env()
            # Create volume (idempotent)
            try:
                client.volumes.get(volume_name)
            except Exception:
                client.volumes.create(name=volume_name)
            # Create container (idempotent)
            try:
                client.containers.get(container_name)
            except Exception:
                client.containers.create(
                    image='alpine',
                    name=container_name,
                    volumes={volume_name: {'bind': '/user_storage', 'mode': 'rw'}},
                    detach=True,
                    command=['sleep', 'infinity']
                )
        except Exception as e:
            return jsonify({'success': False, 'error': f'Failed to set up Docker for user: {str(e)}'})
        # Only add user to DB if Docker setup succeeded
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            public_key=public_key
        )
        db.session.add(user)
        db.session.commit()
        log_security_action('USER_REGISTERED', f'New user registered: {username}')
        return jsonify({'success': True, 'redirect': url_for('login'), 'container_name': container_name})
    return render_template('register.html')

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        user = User.query.filter_by(email=email, is_admin=True).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            log_security_action('ADMIN_LOGIN', f'Admin {user.username} logged in with email {email}')
            return jsonify({'success': True, 'redirect': url_for('admin_dashboard')})
        else:
            log_security_action('ADMIN_LOGIN_FAILED', f'Failed admin login attempt for email {email}')
            return jsonify({'success': False, 'error': 'Invalid admin credentials'})
    
    return render_template('admin_login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user_files = File.query.filter_by(user_id=current_user.id).all()
    stats = {
        'encrypted_files': len(user_files),
        'active_users': User.query.count(),
        'security_level': 'HIGH',
        'threat_alerts': SecurityLog.query.filter_by(action='LOGIN_FAILED').count()
    }
    return render_template('dashboard.html', stats=stats, files=user_files)

@app.route('/admin-dashboard')
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()
    files = File.query.all()
    security_logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).limit(50).all()
    
    # Calculate security statistics
    successful_logins = SecurityLog.query.filter(SecurityLog.action.like('%LOGIN_SUCCESS%')).count()
    failed_logins = SecurityLog.query.filter(SecurityLog.action.like('%LOGIN_FAILED%')).count()
    new_registrations = SecurityLog.query.filter(SecurityLog.action.like('%USER_REGISTERED%')).count()
    file_uploads = SecurityLog.query.filter(SecurityLog.action.like('%FILE_UPLOADED%')).count()
    
    security_stats = {
        'successful_logins': successful_logins,
        'failed_logins': failed_logins,
        'new_registrations': new_registrations,
        'file_uploads': file_uploads
    }
    
    # Generate security alerts based on recent activity
    security_alerts = []
    
    # Check for multiple failed login attempts (potential brute force)
    recent_failed_logins = SecurityLog.query.filter(
        SecurityLog.action.like('%LOGIN_FAILED%'),
        SecurityLog.timestamp >= datetime.datetime.utcnow() - datetime.timedelta(hours=1)
    ).count()
    
    if recent_failed_logins >= 5:
        security_alerts.append({
            'title': 'Multiple Failed Login Attempts',
            'description': f'{recent_failed_logins} failed login attempts in the last hour',
            'severity': 'high',
            'timestamp': datetime.datetime.utcnow()
        })
    
    # Check for unusual file upload activity
    recent_uploads = SecurityLog.query.filter(
        SecurityLog.action.like('%FILE_UPLOADED%'),
        SecurityLog.timestamp >= datetime.datetime.utcnow() - datetime.timedelta(hours=1)
    ).count()
    
    if recent_uploads >= 10:
        security_alerts.append({
            'title': 'High File Upload Activity',
            'description': f'{recent_uploads} files uploaded in the last hour',
            'severity': 'medium',
            'timestamp': datetime.datetime.utcnow()
        })
    
    # Check for new user registrations
    recent_registrations = SecurityLog.query.filter(
        SecurityLog.action.like('%USER_REGISTERED%'),
        SecurityLog.timestamp >= datetime.datetime.utcnow() - datetime.timedelta(hours=24)
    ).count()
    
    if recent_registrations >= 5:
        security_alerts.append({
            'title': 'Multiple New User Registrations',
            'description': f'{recent_registrations} new users registered in the last 24 hours',
            'severity': 'medium',
            'timestamp': datetime.datetime.utcnow()
        })
    
    # Check for admin login activity
    recent_admin_logins = SecurityLog.query.filter(
        SecurityLog.action.like('%ADMIN_LOGIN%'),
        SecurityLog.timestamp >= datetime.datetime.utcnow() - datetime.timedelta(hours=24)
    ).count()
    
    if recent_admin_logins > 0:
        security_alerts.append({
            'title': 'Admin Login Activity',
            'description': f'{recent_admin_logins} admin login(s) in the last 24 hours',
            'severity': 'low',
            'timestamp': datetime.datetime.utcnow()
        })
    
    stats = {
        'total_users': len(users),
        'total_files': len(files),
        'security_alerts': len(security_alerts),
        'system_status': 'SECURE' if len(security_alerts) == 0 else 'ATTENTION'
    }
    
    # Docker integration
    docker_info = {'containers': [], 'volumes': []}
    try:
        client = docker.from_env()
        # List containers
        containers = client.containers.list(all=True)
        for c in containers:
            docker_info['containers'].append({
                'id': c.short_id,
                'name': c.name,
                'status': c.status,
                'image': c.image.tags[0] if c.image.tags else 'untagged',
                'created': c.attrs['Created'][:19].replace('T', ' ')
            })
        # List volumes
        volumes = client.volumes.list()
        for v in volumes:
            docker_info['volumes'].append({
                'name': v.name,
                'mountpoint': v.attrs['Mountpoint']
            })
    except Exception as e:
        docker_info['error'] = str(e)
    
    # Docker system stats for new UI section
    try:
        client = docker.from_env()
        total_containers = len(client.containers.list(all=True))
        running_containers = len(client.containers.list())
        total_images = len(client.images.list())
        docker_status = "Running" if client.ping() else "Stopped"
    except Exception:
        total_containers = "Unavailable"
        running_containers = "Unavailable"
        total_images = "Unavailable"
        docker_status = "Unavailable"
    docker_stats = {
        'containers': total_containers,
        'running': running_containers,
        'images': total_images,
        'status': docker_status
    }
    
    # Docker Containers Management data
    docker_containers = []
    try:
        client = docker.from_env()
        containers = client.containers.list(all=True)
        for c in containers:
            docker_containers.append({
                'id': c.short_id,
                'name': c.name,
                'status': c.status,
                'image': c.image.tags[0] if c.image.tags else 'untagged'
            })
    except Exception as e:
        docker_containers = None
        docker_containers_error = str(e)
    else:
        docker_containers_error = None
    
    # Docker Images data
    docker_images = []
    try:
        client = docker.from_env()
        images = client.images.list()
        for img in images:
            tags = img.tags[0] if img.tags else 'untagged'
            image_id = img.short_id.replace('sha256:', '') if hasattr(img, 'short_id') else img.id[:12]
            size_mb = round(img.attrs['Size'] / (1024*1024), 2) if 'Size' in img.attrs else 'N/A'
            created = img.attrs['Created'][:19].replace('T', ' ') if 'Created' in img.attrs else 'N/A'
            docker_images.append({
                'name': tags,
                'id': image_id,
                'size': size_mb,
                'created': created
            })
    except Exception as e:
        docker_images = None
        docker_images_error = str(e)
    else:
        docker_images_error = None
    
    # Docker All Containers data
    docker_all_containers = []
    docker_running_containers = []
    try:
        client = docker.from_env()
        containers = client.containers.list(all=True)
        for c in containers:
            ports = c.attrs['NetworkSettings']['Ports'] if 'NetworkSettings' in c.attrs and 'Ports' in c.attrs['NetworkSettings'] else {}
            docker_all_containers.append({
                'id': c.short_id,
                'name': c.name,
                'status': c.status,
                'image': c.image.tags[0] if c.image.tags else 'untagged',
                'ports': ports
            })
        running = client.containers.list()
        for c in running:
            ports = c.attrs['NetworkSettings']['Ports'] if 'NetworkSettings' in c.attrs and 'Ports' in c.attrs['NetworkSettings'] else {}
            docker_running_containers.append({
                'id': c.short_id,
                'name': c.name,
                'status': c.status,
                'image': c.image.tags[0] if c.image.tags else 'untagged',
                'ports': ports
            })
    except Exception as e:
        docker_all_containers = None
        docker_running_containers = None
        docker_containers_error = str(e)
    # Docker system info
    docker_system_info = None
    try:
        client = docker.from_env()
        info = client.info()
        docker_system_info = {
            'version': client.version().get('Version', 'N/A'),
            'architecture': info.get('Architecture', 'N/A'),
            'storage_driver': info.get('Driver', 'N/A'),
            'kernel_version': info.get('KernelVersion', 'N/A')
        }
    except Exception as e:
        docker_system_info = None
        docker_system_info_error = str(e)
    else:
        docker_system_info_error = None
    
    return render_template('admin_dashboard.html', 
                         stats=stats, 
                         users=users, 
                         files=files, 
                         logs=security_logs,
                         security_alerts=security_alerts,
                         security_stats=security_stats,
                         docker_info=docker_info,
                         docker_stats=docker_stats,
                         docker_containers=docker_containers,
                         docker_containers_error=docker_containers_error,
                         docker_images=docker_images,
                         docker_images_error=docker_images_error,
                         docker_all_containers=docker_all_containers,
                         docker_running_containers=docker_running_containers,
                         docker_system_info=docker_system_info,
                         docker_system_info_error=docker_system_info_error)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'})
    if file:
        import docker
        import tarfile
        import io
        import datetime
        username = current_user.username
        volume_name = f'user_{username}_volume'
        container_name = f'user_{username}_container'
        try:
            client = docker.from_env()
            # Ensure volume exists
            try:
                client.volumes.get(volume_name)
            except Exception:
                client.volumes.create(name=volume_name)
            # Ensure container exists
            try:
                container = client.containers.get(container_name)
            except Exception:
                container = client.containers.create(
                    image='alpine',
                    name=container_name,
                    volumes={volume_name: {'bind': '/user_storage', 'mode': 'rw'}},
                    detach=True,
                    command=['sleep', 'infinity']
                )
            if container.status != 'running':
                container.start()
            du_cmd = ["sh", "-c", "du -sb /user_storage | cut -f1"]
            temp_container = client.containers.run(
                image='alpine',
                command=du_cmd,
                volumes={volume_name: {'bind': '/user_storage', 'mode': 'rw'}},
                remove=True,
                detach=False,
                stdout=True,
                stderr=True
            )
            used_bytes = int(temp_container.decode().strip().split()[0])
        except Exception as e:
            return jsonify({'success': False, 'error': f'Could not check storage usage or ensure container: {str(e)}'})
        used_gb = used_bytes / (1024*1024*1024)
        warn = False
        if used_gb > 20:
            return jsonify({'success': False, 'error': 'Storage quota exceeded (20GB). Delete files before uploading more.'})
        if used_gb > 15:
            warn = True
        filename = secure_filename(file.filename)
        file_data = file.read()
        key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padded_data = file_data + b'\0' * (16 - len(file_data) % 16)
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        encrypted_b64 = base64.b64encode(iv + key + encrypted_data)
        try:
            container = client.containers.get(container_name)
            tarstream = io.BytesIO()
            with tarfile.open(fileobj=tarstream, mode='w') as tar:
                tarinfo = tarfile.TarInfo(name=filename)
                tarinfo.size = len(encrypted_b64)
                tar.addfile(tarinfo, io.BytesIO(encrypted_b64))
            tarstream.seek(0)
            success = container.put_archive('/user_storage', tarstream.read())
            if not success:
                return jsonify({'success': False, 'error': 'Failed to copy file to container.'})
        except Exception as e:
            return jsonify({'success': False, 'error': f'Failed to copy file to container: {str(e)}'})
        # Save file metadata in DB
        file_record = File(
            filename=filename,
            original_filename=file.filename,
            encrypted_data='',  # Not used anymore
            file_size=len(file_data),
            user_id=current_user.id,
            upload_date=datetime.datetime.utcnow()
        )
        db.session.add(file_record)
        db.session.commit()
        log_security_action('FILE_UPLOADED', f'File uploaded: {filename}')
        return jsonify({'success': True, 'message': 'File uploaded successfully to container', 'storage_warning': warn})
    return jsonify({'success': False, 'error': 'Upload failed'})

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    import docker
    import tarfile
    import io
    file_record = File.query.get_or_404(file_id)
    if file_record.user_id != current_user.id and not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    try:
        username = current_user.username if not current_user.is_admin else file_record.owner.username
        container_name = f'user_{username}_container'
        client = docker.from_env()
        container = client.containers.get(container_name)
        # Get the file from the container
        stream, stat = container.get_archive(f'/user_storage/{file_record.filename}')
        file_bytes = b''
        for chunk in stream:
            file_bytes += chunk
        # Extract from tar
        tarstream = io.BytesIO(file_bytes)
        with tarfile.open(fileobj=tarstream, mode='r') as tar:
            member = tar.getmember(file_record.filename)
            encrypted_b64 = tar.extractfile(member).read()
        # Decrypt
        encrypted_data = base64.b64decode(encrypted_b64)
        iv = encrypted_data[:16]
        key = encrypted_data[16:48]
        ciphertext = encrypted_data[48:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        decrypted_data = decrypted_data.rstrip(b'\0')
        from flask import send_file
        return send_file(
            io.BytesIO(decrypted_data),
            as_attachment=True,
            download_name=file_record.original_filename
        )
    except Exception as e:
        flash('Error decrypting or fetching file', 'error')
        return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    log_security_action('LOGOUT', f'User {current_user.username} logged out')
    logout_user()
    return redirect(url_for('index'))

@app.route('/api/stats')
@login_required
def get_stats():
    user_files = File.query.filter_by(user_id=current_user.id).all()
    stats = {
        'encrypted_files': len(user_files),
        'active_users': User.query.count(),
        'security_level': 'HIGH',
        'threat_alerts': SecurityLog.query.filter_by(action='LOGIN_FAILED').count()
    }
    return jsonify(stats)

@app.route('/api/security-logs')
@login_required
@admin_required
def get_security_logs():
    logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).limit(20).all()
    return jsonify([{
        'id': log.id,
        'action': log.action,
        'details': log.details,
        'timestamp': log.timestamp.isoformat(),
        'user_id': log.user_id
    } for log in logs])

@app.route('/generate-rsa-keys', methods=['POST'])
def generate_rsa_keys():
    try:
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        # Serialize keys to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        log_security_action('RSA_KEYS_GENERATED', 'New RSA key pair generated')
        
        return jsonify({
            'success': True,
            'private_key': private_pem,
            'public_key': public_pem
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/delete-container/<container_id>', methods=['POST'])
@login_required
@admin_required
def delete_container(container_id):
    try:
        client = docker.from_env()
        container = client.containers.get(container_id)
        container.stop()
        container.remove()
        flash(f'Container {container_id} deleted successfully.', 'success')
    except Exception as e:
        flash(f'Error deleting container {container_id}: {str(e)}', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/start-all-containers', methods=['POST'])
@login_required
@admin_required
def start_all_containers():
    try:
        client = docker.from_env()
        containers = client.containers.list(all=True)
        started = 0
        for c in containers:
            if c.status != 'running':
                c.start()
                started += 1
        flash(f'Started {started} container(s).', 'success')
    except Exception as e:
        flash(f'Error starting containers: {str(e)}', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/stop-all-containers', methods=['POST'])
@login_required
@admin_required
def stop_all_containers():
    try:
        client = docker.from_env()
        containers = client.containers.list()
        stopped = 0
        for c in containers:
            c.stop()
            stopped += 1
        flash(f'Stopped {stopped} container(s).', 'success')
    except Exception as e:
        flash(f'Error stopping containers: {str(e)}', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/start-container/<container_id>', methods=['POST'])
@login_required
@admin_required
def start_container(container_id):
    try:
        client = docker.from_env()
        container = client.containers.get(container_id)
        container.start()
        flash(f'Started container {container_id}.', 'success')
    except Exception as e:
        flash(f'Error starting container {container_id}: {str(e)}', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/stop-container/<container_id>', methods=['POST'])
@login_required
@admin_required
def stop_container(container_id):
    try:
        client = docker.from_env()
        container = client.containers.get(container_id)
        container.stop()
        flash(f'Stopped container {container_id}.', 'success')
    except Exception as e:
        flash(f'Error stopping container {container_id}: {str(e)}', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/containers', methods=['GET'])
@login_required
@admin_required
def admin_list_user_containers():
    import docker
    from datetime import datetime
    users = User.query.all()
    results = []
    try:
        client = docker.from_env()
        for user in users:
            username = user.username
            container_name = f'user_{username}_container'
            volume_name = f'user_{username}_volume'
            # Get storage usage
            try:
                du_cmd = ["sh", "-c", "du -sb /user_storage | cut -f1"]
                output = client.containers.run(
                    image='alpine',
                    command=du_cmd,
                    volumes={volume_name: {'bind': '/user_storage', 'mode': 'rw'}},
                    remove=True,
                    detach=False,
                    stdout=True,
                    stderr=True
                )
                storage_usage = int(output.decode().strip().split()[0])
            except Exception:
                storage_usage = None
            # Get last active timestamp
            try:
                container = client.containers.get(container_name)
                last_active = container.attrs['State'].get('FinishedAt') or container.attrs['State'].get('StartedAt')
                if last_active and last_active != '0001-01-01T00:00:00Z':
                    last_active = last_active.replace('T', ' ').replace('Z', '')
                else:
                    last_active = None
            except Exception:
                last_active = None
            results.append({
                'username': username,
                'container_name': container_name,
                'volume_name': volume_name,
                'storage_usage_bytes': storage_usage,
                'last_active': last_active
            })
        return jsonify({'success': True, 'containers': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/files')
@login_required
def api_files():
    files = File.query.filter_by(user_id=current_user.id).all()
    return jsonify({'files': [
        {
            'id': f.id,
            'original_filename': f.original_filename,
            'file_size': f.file_size,
            'upload_date': f.upload_date.strftime('%Y-%m-%d %H:%M:%S') if f.upload_date else None
        } for f in files
    ]})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False, host='0.0.0.0', port=5000) 