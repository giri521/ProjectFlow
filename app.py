import os
import random
import string
import smtplib
import requests
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory, abort, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from fpdf import FPDF
import PyPDF2
import os
import tempfile
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Backendless Configuration
BACKENDLESS_APP_ID = "EE1B45EF-1CFF-4136-B4D8-0884284D6647"
BACKENDLESS_API_KEY = "E470F076-0348-426B-AD5B-6FA5715D009A"
BACKENDLESS_API_URL = f"https://api.backendless.com/{BACKENDLESS_APP_ID}/{BACKENDLESS_API_KEY}"

# OpenRouter AI Configuration
app.config['OPENROUTER_API_KEY'] = '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'
app.config['OPENROUTER_API_URL'] = 'https://openrouter.ai/api/v1/chat/completions'
app.config['OPENROUTER_MODEL'] = 'openai/gpt-3.5-turbo'

# Email configuration for OTP
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@gmail.com'

# Ensure upload directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'profile_photos'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'project_documents'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'team_photos'), exist_ok=True)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'base'

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'txt'}

# OTP Storage (in-memory, can be moved to Backendless if needed)
otp_storage = {}  # Format: {email: {'otp': '123456', 'timestamp': 1234567890}}

# ============================================================================
# BACKENDLESS HELPER FUNCTIONS
# ============================================================================

def backendless_request(method, endpoint, data=None, params=None):
    """Make a request to Backendless REST API"""
    url = f"{BACKENDLESS_API_URL}/{endpoint}"
    
    headers = {
        'Content-Type': 'application/json'
    }
    
    try:
        if method.upper() == 'GET':
            response = requests.get(url, headers=headers, params=params)
        elif method.upper() == 'POST':
            response = requests.post(url, headers=headers, json=data)
        elif method.upper() == 'PUT':
            response = requests.put(url, headers=headers, json=data)
        elif method.upper() == 'DELETE':
            response = requests.delete(url, headers=headers)
        else:
            return {'success': False, 'error': 'Invalid method'}, 400
        
        if response.status_code in [200, 201]:
            return response.json(), response.status_code
        else:
            print(f"Backendless API Error: {response.status_code} - {response.text}")
            return {'success': False, 'error': response.text}, response.status_code
            
    except requests.exceptions.RequestException as e:
        print(f"Backendless Request Exception: {str(e)}")
        return {'success': False, 'error': str(e)}, 500

def create_object(table_name, data):
    """Create a new object in Backendless"""
    return backendless_request('POST', f'data/{table_name}', data=data)

def get_objects(table_name, where_clause=None, page_size=100, offset=0):
    """Get objects from Backendless with optional where clause"""
    params = {
        'pageSize': page_size,
        'offset': offset
    }
    if where_clause:
        params['where'] = where_clause
    
    return backendless_request('GET', f'data/{table_name}', params=params)

def get_object_by_id(table_name, object_id):
    """Get a single object by ID"""
    return backendless_request('GET', f'data/{table_name}/{object_id}')

def update_object(table_name, object_id, data):
    """Update an object in Backendless"""
    return backendless_request('PUT', f'data/{table_name}/{object_id}', data=data)

def delete_object(table_name, object_id):
    """Delete an object from Backendless"""
    return backendless_request('DELETE', f'data/{table_name}/{object_id}')

def upload_file_to_backendless(file, folder_name):
    """Upload a file to Backendless and return the file URL"""
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_filename = secure_filename(file.filename)
        filename = f"{timestamp}_{safe_filename}"
        
        # Save locally first (temporarily)
        local_path = os.path.join(app.config['UPLOAD_FOLDER'], folder_name, filename)
        file.save(local_path)
        
        # Upload to Backendless file service
        url = f"{BACKENDLESS_API_URL}/files/{folder_name}/{filename}"
        
        with open(local_path, 'rb') as f:
            files = {'file': (filename, f, 'application/octet-stream')}
            response = requests.post(url, files=files)
        
        if response.status_code in [200, 201]:
            file_url = response.json().get('fileURL')
            return {
                'success': True,
                'filename': filename,
                'url': file_url,
                'local_path': local_path
            }
        else:
            return {'success': False, 'error': response.text}
            
    except Exception as e:
        print(f"File upload error: {str(e)}")
        return {'success': False, 'error': str(e)}

# ============================================================================
# USER CLASS FOR FLASK-LOGIN
# ============================================================================

class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data.get('objectId')
        self.username = user_data.get('username')
        self.email = user_data.get('email')
        self.mobile = user_data.get('mobile')
        self.password = user_data.get('password')
        self.profile_photo = user_data.get('profile_photo')
        self.created_at = user_data.get('created')

@login_manager.user_loader
def load_user(user_id):
    """Load user from Backendless by ID"""
    result, status = get_object_by_id('Users', user_id)
    if status == 200:
        return User(result)
    return None

def get_user_by_email_or_username(email_or_username):
    """Get user by email or username"""
    # Try by email first
    result, status = get_objects('Users', f"email = '{email_or_username}'")
    if status == 200 and result and len(result) > 0:
        return User(result[0])
    
    # Try by username
    result, status = get_objects('Users', f"username = '{email_or_username}'")
    if status == 200 and result and len(result) > 0:
        return User(result[0])
    
    return None

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_otp():
    """Generate a 6-digit OTP"""
    return ''.join(random.choices(string.digits, k=6))

def send_email_otp(recipient_email, otp):
    """Send OTP via email using SMTP"""
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = app.config['MAIL_USERNAME']
        msg['To'] = recipient_email
        msg['Subject'] = 'Your OTP for ProjectFlow Registration'
        
        # Email body
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
                <h1 style="color: white; margin: 0;">ProjectFlow</h1>
            </div>
            <div style="background: #f5f5f5; padding: 30px; border-radius: 0 0 10px 10px;">
                <h2 style="color: #333; margin-top: 0;">Email Verification</h2>
                <p style="color: #666; font-size: 16px;">Your One-Time Password (OTP) for registration is:</p>
                <div style="background: white; padding: 20px; text-align: center; border-radius: 10px; margin: 20px 0;">
                    <h1 style="color: #667eea; font-size: 36px; letter-spacing: 5px; margin: 0;">{otp}</h1>
                </div>
                <p style="color: #666; font-size: 14px;">This OTP is valid for 10 minutes. Please do not share it with anyone.</p>
                <p style="color: #999; font-size: 12px; margin-top: 30px;">If you didn't request this, please ignore this email.</p>
            </div>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        # Send email
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.send_message(msg)
        server.quit()
        
        print(f"✅ OTP sent successfully to {recipient_email}")
        return True
        
    except Exception as e:
        print(f"❌ Failed to send email: {str(e)}")
        # Fallback to console printing
        print(f"\n{'='*50}")
        print(f"OTP for {recipient_email}: {otp}")
        print(f"{'='*50}\n")
        return False

def summarize_with_openrouter(text, max_length=500):
    """
    Use OpenRouter AI to generate an intelligent summary with extracted tools and technologies.
    Returns a dictionary with summary, key points, and tools/technologies.
    """
    if not text or len(text.strip()) < 50:
        return {
            'summary': 'Document content is too short for meaningful analysis.',
            'key_points': ['Insufficient content to extract key points.'],
            'tools_technologies': ['No tools or technologies identified.'],
            'technical_jargon': []
        }
    
    # Truncate text if too long (OpenRouter has token limits)
    if len(text) > 15000:
        text = text[:15000] + "..."
    
    try:
        headers = {
            'Authorization': f'Bearer {app.config["OPENROUTER_API_KEY"]}',
            'Content-Type': 'application/json',
            'HTTP-Referer': 'http://localhost:5000',
            'X-Title': 'ProjectFlow Document Summarizer'
        }
        
        prompt = f"""You are an expert technical document analyst. Analyze the following document and provide a comprehensive response in JSON format.

Document content:
{text}

Please analyze this document and provide:

1. A concise summary (5-7 sentences) highlighting the main points and objectives
2. Key findings and important points (list 8-12 bullet points)
3. All tools, technologies, frameworks, programming languages, libraries, and platforms mentioned
4. Technical jargon and specialized terminology used

Return your response in this exact JSON format:
{{
    "summary": "your summary here",
    "key_points": ["point 1", "point 2", "point 3", ...],
    "tools_technologies": ["tool 1", "tool 2", "tool 3", ...],
    "technical_jargon": ["term 1", "term 2", "term 3", ...]
}}

Make the summary technical and precise, using appropriate industry terminology."""
        
        payload = {
            'model': app.config['OPENROUTER_MODEL'],
            'messages': [
                {'role': 'system', 'content': 'You are a technical document analyzer that outputs JSON only.'},
                {'role': 'user', 'content': prompt}
            ],
            'temperature': 0.3,
            'max_tokens': 1000,
            'response_format': {'type': 'json_object'}
        }
        
        response = requests.post(
            app.config['OPENROUTER_API_URL'],
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            ai_response = result['choices'][0]['message']['content']
            
            # Parse JSON response
            try:
                parsed = json.loads(ai_response)
                return {
                    'summary': parsed.get('summary', 'Summary generation failed.'),
                    'key_points': parsed.get('key_points', ['No key points extracted.']),
                    'tools_technologies': parsed.get('tools_technologies', ['No tools identified.']),
                    'technical_jargon': parsed.get('technical_jargon', [])
                }
            except json.JSONDecodeError:
                print(f"Failed to parse AI response as JSON: {ai_response}")
                return {
                    'summary': 'AI response parsing failed.',
                    'key_points': ['Error in AI response format.'],
                    'tools_technologies': ['Try again later.'],
                    'technical_jargon': []
                }
        else:
            print(f"OpenRouter API error: {response.status_code} - {response.text}")
            return {
                'summary': 'AI summarization service temporarily unavailable.',
                'key_points': ['Please try again later.'],
                'tools_technologies': ['Service unavailable.'],
                'technical_jargon': []
            }
            
    except requests.exceptions.RequestException as e:
        print(f"OpenRouter API request failed: {str(e)}")
        return {
            'summary': 'Network error during AI summarization.',
            'key_points': ['Please check your connection and try again.'],
            'tools_technologies': ['Network error.'],
            'technical_jargon': []
        }
    except Exception as e:
        print(f"Unexpected error in AI summarization: {str(e)}")
        return {
            'summary': 'An unexpected error occurred.',
            'key_points': ['Please try again.'],
            'tools_technologies': ['Error occurred.'],
            'technical_jargon': []
        }

def extract_text_from_file(filename, file_display_name):
    """Extract text content from various file types"""
    # Get the full file path from the project_documents directory
    full_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'project_documents', filename)
    
    try:
        if os.path.exists(full_file_path):
            file_extension = os.path.splitext(file_display_name)[1].lower()
            
            if file_extension == '.txt':
                with open(full_file_path, 'r', encoding='utf-8') as f:
                    return f.read()
            elif file_extension == '.pdf':
                with open(full_file_path, 'rb') as f:
                    pdf_reader = PyPDF2.PdfReader(f)
                    text = ""
                    for page in pdf_reader.pages[:10]:  # Read first 10 pages
                        text += page.extract_text() + "\n"
                    return text
            else:
                return f"Text extraction not available for {file_extension} files."
        else:
            return f"File not found on server: {full_file_path}"
    except Exception as e:
        return f"Error reading file: {str(e)}"

def clean_text_for_pdf(text):
    """Clean text to remove characters that cause encoding issues in PDF"""
    if not text:
        return ""
    # Replace common problematic characters
    replacements = {
        '•': '-',
        '●': '-',
        '○': '-',
        '◆': '-',
        '▪': '-',
        '✓': '√',
        '✗': 'X',
        '✘': 'X',
        '★': '*',
        '☆': '*',
        '❤': '<3',
        '☺': ':)',
        '☹': ':(',
        '♠': '(spade)',
        '♣': '(club)',
        '♥': '<3',
        '♦': '(diamond)',
        '→': '->',
        '←': '<-',
        '↑': '^',
        '↓': 'v',
        '↔': '<->',
        '“': '"',
        '”': '"',
        '‘': "'",
        '’': "'",
        '…': '...',
        '—': '-',
        '–': '-',
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    
    # Remove any remaining non-Latin-1 characters
    return text.encode('latin-1', errors='ignore').decode('latin-1')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Admin access required', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# ============================================================================
# ROUTES
# ============================================================================

@app.route('/')
def base():
    return render_template('base.html')

@app.route('/signup', methods=['POST'])
def signup():
    try:
        username = request.form.get('username')
        email = request.form.get('email')
        mobile = request.form.get('mobile')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        otp = request.form.get('otp')
        
        print(f"Signup attempt - Email: {email}, OTP entered: {otp}")
        
        # Validate required fields
        if not all([username, email, mobile, password, confirm_password, otp]):
            flash('All fields are required', 'danger')
            return redirect(url_for('base'))
        
        # Check if user exists in Backendless
        existing_user, status = get_objects('Users', f"username = '{username}'")
        if status == 200 and existing_user and len(existing_user) > 0:
            flash('Username already exists', 'danger')
            return redirect(url_for('base'))
        
        existing_email, status = get_objects('Users', f"email = '{email}'")
        if status == 200 and existing_email and len(existing_email) > 0:
            flash('Email already registered', 'danger')
            return redirect(url_for('base'))
        
        # Validate OTP
        stored_data = otp_storage.get(email)
        
        print(f"Stored OTP data: {stored_data}")
        
        if not stored_data:
            flash('No OTP found. Please request a new OTP.', 'danger')
            return redirect(url_for('base'))
        
        # Check if OTP is expired (10 minutes)
        current_time = datetime.now().timestamp()
        otp_time = stored_data.get('timestamp', 0)
        
        if current_time - otp_time > 600:  # 10 minutes in seconds
            flash('OTP has expired. Please request a new one.', 'danger')
            # Clean up expired OTP
            otp_storage.pop(email, None)
            return redirect(url_for('base'))
        
        stored_otp = str(stored_data.get('otp')).strip()
        entered_otp = str(otp).strip()
        
        # Compare OTPs
        if stored_otp != entered_otp:
            print(f"OTP mismatch: stored='{stored_otp}', entered='{entered_otp}'")
            flash('Invalid OTP. Please check and try again.', 'danger')
            return redirect(url_for('base'))
        
        # Validate password
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('base'))
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
            return redirect(url_for('base'))
        
        # Create user in Backendless
        hashed_password = generate_password_hash(password)
        user_data = {
            'username': username,
            'email': email,
            'mobile': mobile,
            'password': hashed_password
        }
        
        result, status = create_object('Users', user_data)
        
        if status == 200:
            # Clear OTP
            otp_storage.pop(email, None)
            flash('Registration successful! Please login.', 'success')
        else:
            flash('Registration failed. Please try again.', 'danger')
        
        return redirect(url_for('base'))
        
    except Exception as e:
        print(f"Error in signup: {str(e)}")
        flash('An error occurred during registration. Please try again.', 'danger')
        return redirect(url_for('base'))

@app.route('/send-otp', methods=['POST'])
def send_otp():
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'success': False, 'message': 'Email is required'}), 400
        
        # Check if email already registered in Backendless
        existing, status = get_objects('Users', f"email = '{email}'")
        if status == 200 and existing and len(existing) > 0:
            return jsonify({'success': False, 'message': 'Email already registered'}), 400
        
        # Generate OTP
        otp = generate_otp()
        
        # Store OTP with timestamp
        otp_storage[email] = {
            'otp': otp,
            'timestamp': datetime.now().timestamp()
        }
        
        # Print to console for debugging
        print(f"\n{'='*50}")
        print(f"OTP GENERATED FOR {email}: {otp}")
        print(f"{'='*50}\n")
        
        # Try to send email, but don't fail if it doesn't work
        try:
            send_email_otp(email, otp)
        except Exception as e:
            print(f"Email sending failed but continuing: {e}")
        
        return jsonify({
            'success': True, 
            'message': f'OTP sent successfully! (For testing: {otp})'
        })
            
    except Exception as e:
        print(f"Error in send_otp: {str(e)}")
        return jsonify({'success': False, 'message': 'Server error'}), 500

@app.route('/user-login', methods=['POST'])
def user_login():
    username_or_email = request.form.get('username')
    password = request.form.get('password')
    
    if not username_or_email or not password:
        flash('Please enter both username/email and password', 'danger')
        return redirect(url_for('base'))
    
    user = get_user_by_email_or_username(username_or_email)
    
    if user and check_password_hash(user.password, password):
        login_user(user)
        return redirect(url_for('user_dashboard'))
    
    flash('Invalid credentials', 'danger')
    return redirect(url_for('base'))

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Fixed admin credentials
        if username == 'admin' and password == 'admin123':
            session['is_admin'] = True
            return redirect(url_for('admin_dashboard'))
        
        flash('Invalid admin credentials', 'danger')
    
    return render_template('admin_login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('base'))

@app.route('/admin-logout')
def admin_logout():
    session.pop('is_admin', None)
    return redirect(url_for('admin_login'))

# ============================================================================
# FILE SERVING ROUTES
# ============================================================================

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    """Serve files from the uploads directory"""
    try:
        if '..' in filename or filename.startswith('/'):
            abort(404)
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        print(f"Error serving file {filename}: {str(e)}")
        return "File not found", 404

@app.route('/uploads/profile_photos/<path:filename>')
def profile_photo(filename):
    """Serve profile photos from the uploads/profile_photos directory"""
    try:
        if '..' in filename or filename.startswith('/'):
            abort(404)
        return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], 'profile_photos'), filename)
    except Exception as e:
        print(f"Error serving profile photo {filename}: {str(e)}")
        return "File not found", 404

@app.route('/uploads/project_documents/<path:filename>')
def project_document(filename):
    """Serve project documents from the uploads/project_documents directory"""
    try:
        if '..' in filename or filename.startswith('/'):
            abort(404)
        return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], 'project_documents'), filename)
    except Exception as e:
        print(f"Error serving project document {filename}: {str(e)}")
        return "File not found", 404

@app.route('/uploads/team_photos/<path:filename>')
def team_photo(filename):
    """Serve team member photos from the uploads/team_photos directory"""
    try:
        if '..' in filename or filename.startswith('/'):
            abort(404)
        return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], 'team_photos'), filename)
    except Exception as e:
        print(f"Error serving team photo {filename}: {str(e)}")
        return "File not found", 404

# ============================================================================
# USER ROUTES
# ============================================================================

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    # Get user's projects from Backendless
    projects_result, status = get_objects('Projects', f"user_id = '{current_user.id}'", page_size=100)
    
    projects = projects_result if status == 200 else []
    
    total_projects = len(projects)
    accepted = len([p for p in projects if p.get('status') == 'Accepted'])
    rejected = len([p for p in projects if p.get('status') == 'Rejected'])
    in_progress = len([p for p in projects if p.get('status') == 'In Progress'])
    
    # Get unread message count for each project
    for project in projects:
        messages_result, msg_status = get_objects('Messages', 
            f"project_id = '{project.get('objectId')}' AND sender = 'admin' AND is_read = false")
        project['unread_count'] = len(messages_result) if msg_status == 200 else 0
    
    return render_template('user.html', 
                         section='dashboard',
                         total_projects=total_projects,
                         accepted=accepted,
                         rejected=rejected,
                         in_progress=in_progress,
                         projects=projects)

@app.route('/user/projects')
@login_required
def user_projects():
    projects_result, status = get_objects('Projects', f"user_id = '{current_user.id}'", page_size=100)
    projects = projects_result if status == 200 else []
    return render_template('user.html', section='projects', projects=projects)

@app.route('/user/request-project', methods=['POST'])
@login_required
def request_project():
    title = request.form.get('title')
    description = request.form.get('description')
    
    if not title or not description:
        flash('Please provide both title and description', 'danger')
        return redirect(url_for('user_projects'))
    
    project_data = {
        'user_id': current_user.id,
        'title': title,
        'description': description,
        'status': 'Requested',
        'created_at': datetime.now().isoformat()
    }
    
    project_result, status = create_object('Projects', project_data)
    
    if status == 200:
        project_id = project_result.get('objectId')
        
        # Add default tracking steps
        default_steps = [
            'Request Received',
            'Requirement Analysis',
            'Frontend Development',
            'Backend Development',
            'Testing',
            'Deployment'
        ]
        
        for step in default_steps:
            tracking_data = {
                'project_id': project_id,
                'step_name': step,
                'step_status': 'Pending',
                'created_at': datetime.now().isoformat()
            }
            create_object('ProjectTracking', tracking_data)
        
        # Send welcome message
        message_data = {
            'project_id': project_id,
            'sender': 'admin',
            'message': "✅ Welcome! Your project has been created successfully. We'll review your request and get back to you soon.",
            'timestamp': datetime.now().isoformat(),
            'is_read': False
        }
        create_object('Messages', message_data)
        
        flash('Project requested successfully!', 'success')
    else:
        flash('Failed to create project. Please try again.', 'danger')
    
    return redirect(url_for('user_projects'))

@app.route('/user/track-projects')
@login_required
def user_track_projects():
    projects_result, status = get_objects('Projects', f"user_id = '{current_user.id}'", page_size=100)
    projects = projects_result if status == 200 else []
    
    # Calculate progress for each project
    for project in projects:
        tracking_result, track_status = get_objects('ProjectTracking', f"project_id = '{project.get('objectId')}'")
        if track_status == 200 and tracking_result:
            total_steps = len(tracking_result)
            completed_steps = len([s for s in tracking_result if s.get('step_status') == 'Completed'])
            project['progress'] = (completed_steps / total_steps * 100) if total_steps > 0 else 0
        else:
            project['progress'] = 0
    
    return render_template('user.html', section='track', projects=projects)

@app.route('/user/project/<project_id>/track')
@login_required
def view_project_tracking(project_id):
    project_result, status = get_object_by_id('Projects', project_id)
    
    if status != 200:
        flash('Project not found', 'danger')
        return redirect(url_for('user_dashboard'))
    
    # Verify ownership
    if project_result.get('user_id') != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('user_dashboard'))
    
    project = project_result
    
    tracking_result, track_status = get_objects('ProjectTracking', f"project_id = '{project_id}'")
    tracking_steps = tracking_result if track_status == 200 else []
    
    documents_result, doc_status = get_objects('ProjectDocuments', f"project_id = '{project_id}'")
    documents = documents_result if doc_status == 200 else []
    
    # Calculate progress
    total_steps = len(tracking_steps)
    completed_steps = len([s for s in tracking_steps if s.get('step_status') == 'Completed'])
    progress = (completed_steps / total_steps * 100) if total_steps > 0 else 0
    
    return render_template('user.html', 
                         section='track_detail',
                         project=project,
                         tracking_steps=tracking_steps,
                         documents=documents,
                         progress=progress)

@app.route('/user/summarize-documents')
@login_required
def user_summarize_documents():
    projects_result, status = get_objects('Projects', f"user_id = '{current_user.id}'", page_size=100)
    projects = projects_result if status == 200 else []
    
    # Get documents for each project
    for project in projects:
        docs_result, doc_status = get_objects('ProjectDocuments', f"project_id = '{project.get('objectId')}'")
        project['documents'] = docs_result if doc_status == 200 else []
    
    return render_template('user.html', 
                         section='summarize', 
                         projects=projects)

@app.route('/user/project/<project_id>/documents')
@login_required
def view_project_documents(project_id):
    project_result, status = get_object_by_id('Projects', project_id)
    
    if status != 200:
        flash('Project not found', 'danger')
        return redirect(url_for('user_dashboard'))
    
    # Verify ownership
    if project_result.get('user_id') != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('user_dashboard'))
    
    documents_result, doc_status = get_objects('ProjectDocuments', f"project_id = '{project_id}'")
    documents = documents_result if doc_status == 200 else []
    
    return render_template('user.html', 
                         section='documents',
                         project=project_result,
                         documents=documents)

@app.route('/user/document/<doc_id>/summarize')
@login_required
def summarize_document(doc_id):
    document_result, status = get_object_by_id('ProjectDocuments', doc_id)
    
    if status != 200:
        flash('Document not found', 'danger')
        return redirect(url_for('user_dashboard'))
    
    project_result, proj_status = get_object_by_id('Projects', document_result.get('project_id'))
    
    if proj_status != 200:
        flash('Project not found', 'danger')
        return redirect(url_for('user_dashboard'))
    
    # Verify ownership
    if project_result.get('user_id') != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('user_dashboard'))
    
    document = document_result
    project = project_result
    
    # Check if we already have an AI summary
    if document.get('ai_summary') and document.get('key_points') and document.get('tools_technologies'):
        # Parse stored data
        try:
            key_points = json.loads(document.get('key_points')) if document.get('key_points') else []
            tools_technologies = json.loads(document.get('tools_technologies')) if document.get('tools_technologies') else []
            technical_jargon = json.loads(document.get('technical_jargon')) if document.get('technical_jargon') else []
            summary = document.get('ai_summary')
        except:
            key_points = []
            tools_technologies = []
            technical_jargon = []
            summary = document.get('ai_summary')
    else:
        # Extract text and generate AI summary
        full_text = extract_text_from_file(document.get('file_path'), document.get('file_name'))
        
        if full_text and not full_text.startswith(("Preview not available", "File not found", "Error reading")):
            ai_result = summarize_with_openrouter(full_text)
            
            # Store results in Backendless
            update_data = {
                'ai_summary': ai_result['summary'],
                'key_points': json.dumps(ai_result['key_points']),
                'tools_technologies': json.dumps(ai_result['tools_technologies']),
                'technical_jargon': json.dumps(ai_result.get('technical_jargon', []))
            }
            update_object('ProjectDocuments', doc_id, update_data)
            
            key_points = ai_result['key_points']
            tools_technologies = ai_result['tools_technologies']
            technical_jargon = ai_result.get('technical_jargon', [])
            summary = ai_result['summary']
        else:
            summary = full_text
            key_points = ["Unable to extract text from document."]
            tools_technologies = ["Document may be empty or in an unsupported format."]
            technical_jargon = []
    
    # Get messages for this project
    messages_result, msg_status = get_objects('Messages', f"project_id = '{project.get('objectId')}'", page_size=50)
    messages = messages_result if msg_status == 200 else []
    # Sort by timestamp
    messages.sort(key=lambda x: x.get('timestamp', ''))
    
    # Get full text for display
    full_text = extract_text_from_file(document.get('file_path'), document.get('file_name'))
    
    return render_template('user.html',
                         section='summarize_detail',
                         document=document,
                         project=project,
                         summary=summary,
                         key_points=key_points,
                         tools_technologies=tools_technologies,
                         technical_jargon=technical_jargon,
                         full_text=full_text,
                         messages=messages)

@app.route('/user/regenerate-summary/<doc_id>', methods=['POST'])
@login_required
def regenerate_summary(doc_id):
    document_result, status = get_object_by_id('ProjectDocuments', doc_id)
    
    if status != 200:
        return jsonify({'success': False, 'error': 'Document not found'})
    
    project_result, proj_status = get_object_by_id('Projects', document_result.get('project_id'))
    
    if proj_status != 200:
        return jsonify({'success': False, 'error': 'Project not found'})
    
    # Verify ownership
    if project_result.get('user_id') != current_user.id:
        return jsonify({'success': False, 'error': 'Unauthorized'})
    
    # Extract text and regenerate AI summary
    full_text = extract_text_from_file(document_result.get('file_path'), document_result.get('file_name'))
    
    if full_text and not full_text.startswith(("Preview not available", "File not found", "Error reading")):
        ai_result = summarize_with_openrouter(full_text)
        
        # Store results in Backendless
        update_data = {
            'ai_summary': ai_result['summary'],
            'key_points': json.dumps(ai_result['key_points']),
            'tools_technologies': json.dumps(ai_result['tools_technologies']),
            'technical_jargon': json.dumps(ai_result.get('technical_jargon', []))
        }
        update_object('ProjectDocuments', doc_id, update_data)
        
        return jsonify({
            'success': True,
            'summary': ai_result['summary'],
            'key_points': ai_result['key_points'],
            'tools_technologies': ai_result['tools_technologies'],
            'technical_jargon': ai_result.get('technical_jargon', [])
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Could not extract text from document'
        })

@app.route('/user/download-summary/<doc_id>')
@login_required
def download_summary_pdf(doc_id):
    document_result, status = get_object_by_id('ProjectDocuments', doc_id)
    
    if status != 200:
        flash('Document not found', 'danger')
        return redirect(url_for('user_dashboard'))
    
    project_result, proj_status = get_object_by_id('Projects', document_result.get('project_id'))
    
    if proj_status != 200:
        flash('Project not found', 'danger')
        return redirect(url_for('user_dashboard'))
    
    # Verify ownership
    if project_result.get('user_id') != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('user_dashboard'))
    
    document = document_result
    project = project_result
    
    # Get the summary data
    if document.get('ai_summary') and document.get('key_points') and document.get('tools_technologies'):
        try:
            key_points = json.loads(document.get('key_points')) if document.get('key_points') else []
            tools_technologies = json.loads(document.get('tools_technologies')) if document.get('tools_technologies') else []
            technical_jargon = json.loads(document.get('technical_jargon')) if document.get('technical_jargon') else []
            summary = document.get('ai_summary')
        except:
            key_points = []
            tools_technologies = []
            technical_jargon = []
            summary = document.get('ai_summary')
    else:
        # If no AI summary exists, generate it
        full_text = extract_text_from_file(document.get('file_path'), document.get('file_name'))
        if full_text and not full_text.startswith(("Preview not available", "File not found", "Error reading")):
            ai_result = summarize_with_openrouter(full_text)
            summary = ai_result['summary']
            key_points = ai_result['key_points']
            tools_technologies = ai_result['tools_technologies']
            technical_jargon = ai_result.get('technical_jargon', [])
        else:
            summary = "Unable to generate summary"
            key_points = []
            tools_technologies = []
            technical_jargon = []
    
    # Create PDF with Unicode support
    pdf = FPDF()
    pdf.add_page()
    
    # Set auto page break
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # Add a Unicode font (using built-in fonts with proper encoding)
    pdf.set_font("Helvetica", "B", 16)
    
    # Title
    pdf.cell(200, 10, "ProjectFlow - AI Document Summary", ln=True, align="C")
    pdf.ln(10)
    
    # Document info - clean text for PDF
    pdf.set_font("Helvetica", "B", 12)
    safe_file_name = clean_text_for_pdf(document.get('file_name', 'Unknown'))
    pdf.cell(200, 10, f"Document: {safe_file_name}", ln=True)
    
    pdf.set_font("Helvetica", "", 10)
    safe_project_title = clean_text_for_pdf(project.get('title', 'Unknown'))
    pdf.cell(200, 10, f"Project: {safe_project_title}", ln=True)
    pdf.cell(200, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", ln=True)
    pdf.ln(10)
    
    # AI Summary
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(200, 10, "AI-Generated Technical Summary", ln=True)
    pdf.set_font("Helvetica", "", 11)
    safe_summary = clean_text_for_pdf(summary)
    pdf.multi_cell(0, 5, safe_summary)
    pdf.ln(5)
    
    # Key Points
    if key_points:
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(200, 10, f"Key Findings & Insights ({len(key_points)} points)", ln=True)
        pdf.set_font("Helvetica", "", 11)
        for i, point in enumerate(key_points, 1):
            safe_point = clean_text_for_pdf(point)
            safe_point = safe_point.replace('•', '-').replace('●', '-').replace('○', '-')
            pdf.multi_cell(0, 5, f"{i}. {safe_point}")
        pdf.ln(5)
    
    # Tools & Technologies
    if tools_technologies and tools_technologies[0] != "No tools or technologies identified.":
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(200, 10, "Tools & Technologies Identified", ln=True)
        pdf.set_font("Helvetica", "", 11)
        for tool in tools_technologies:
            safe_tool = clean_text_for_pdf(tool)
            safe_tool = safe_tool.replace('•', '-').replace('●', '-').replace('○', '-')
            pdf.multi_cell(0, 5, f"- {safe_tool}")
        pdf.ln(5)
    
    # Technical Jargon
    if technical_jargon:
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(200, 10, "Technical Terminology", ln=True)
        pdf.set_font("Helvetica", "", 11)
        for term in technical_jargon:
            safe_term = clean_text_for_pdf(term)
            safe_term = safe_term.replace('•', '-').replace('●', '-').replace('○', '-')
            pdf.multi_cell(0, 5, f"- {safe_term}")
        pdf.ln(5)
    
    # Generate filename for download
    safe_filename = secure_filename(document.get('file_name', 'document')).replace('.', '_')
    download_filename = f"summary_{safe_filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    
    # Output PDF to a temporary file first (to avoid encoding issues)
    try:
        # Try to output directly
        pdf_output = pdf.output(dest='S')
        # Try to encode to Latin-1
        try:
            pdf_bytes = pdf_output.encode('latin-1')
        except UnicodeEncodeError:
            # If direct encoding fails, try with replacement
            pdf_bytes = pdf_output.encode('latin-1', errors='replace')
    except Exception as e:
        # If all else fails, create a simple error PDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(200, 10, "Error Generating PDF", ln=True, align="C")
        pdf.ln(10)
        pdf.set_font("Helvetica", "", 12)
        pdf.multi_cell(0, 10, "An error occurred while generating the PDF. Please try again.")
        pdf_bytes = pdf.output(dest='S').encode('latin-1', errors='replace')
    
    # Create response
    response = make_response(pdf_bytes)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename={download_filename}'
    
    return response

@app.route('/user/send-message', methods=['POST'])
@login_required
def send_message():
    project_id = request.form.get('project_id')
    message_text = request.form.get('message')
    
    if not project_id or not message_text:
        return jsonify({'success': False, 'error': 'Missing data'})
    
    # Verify project ownership
    project_result, status = get_object_by_id('Projects', project_id)
    if status != 200 or project_result.get('user_id') != current_user.id:
        return jsonify({'success': False, 'error': 'Unauthorized'})
    
    message_data = {
        'project_id': project_id,
        'sender': 'user',
        'message': message_text,
        'timestamp': datetime.now().isoformat(),
        'is_read': False
    }
    
    result, msg_status = create_object('Messages', message_data)
    
    if msg_status == 200:
        return jsonify({
            'success': True, 
            'message': message_text, 
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M')
        })
    else:
        return jsonify({'success': False, 'error': 'Failed to send message'})

@app.route('/user/chat')
@login_required
def user_chat():
    projects_result, status = get_objects('Projects', f"user_id = '{current_user.id}'", page_size=100)
    projects = projects_result if status == 200 else []
    
    messages_dict = {}
    unread_counts = {}
    
    print(f"Loading chat for user {current_user.username}")
    print(f"Found {len(projects)} projects")
    
    for project in projects:
        project_id = project.get('objectId')
        # Get all messages for this project
        messages_result, msg_status = get_objects('Messages', f"project_id = '{project_id}'", page_size=100)
        
        if msg_status == 200 and messages_result:
            # Sort by timestamp
            sorted_messages = sorted(messages_result, key=lambda x: x.get('timestamp', ''))
            messages_dict[project_id] = sorted_messages
            print(f"Project {project_id} ({project.get('title')}) has {len(sorted_messages)} messages")
        
        # Count unread admin messages
        unread_result, unread_status = get_objects('Messages', 
            f"project_id = '{project_id}' AND sender = 'admin' AND is_read = false")
        unread_counts[project_id] = len(unread_result) if unread_status == 200 else 0
    
    return render_template('user.html', 
                         section='chat', 
                         projects=projects,
                         messages=messages_dict,
                         unread_counts=unread_counts)

@app.route('/user/mark-messages-read/<project_id>', methods=['POST'])
@login_required
def mark_messages_read(project_id):
    # Verify project ownership
    project_result, status = get_object_by_id('Projects', project_id)
    if status != 200 or project_result.get('user_id') != current_user.id:
        return jsonify({'success': False, 'error': 'Unauthorized'})
    
    # Get all unread admin messages
    messages_result, msg_status = get_objects('Messages', 
        f"project_id = '{project_id}' AND sender = 'admin' AND is_read = false")
    
    if msg_status == 200 and messages_result:
        for message in messages_result:
            update_object('Messages', message.get('objectId'), {'is_read': True})
    
    return jsonify({'success': True})

@app.route('/user/get-unread-counts')
@login_required
def user_get_unread_counts():
    projects_result, status = get_objects('Projects', f"user_id = '{current_user.id}'", page_size=100)
    projects = projects_result if status == 200 else []
    
    unread_counts = {}
    
    for project in projects:
        project_id = project.get('objectId')
        messages_result, msg_status = get_objects('Messages', 
            f"project_id = '{project_id}' AND sender = 'admin' AND is_read = false")
        unread_counts[project_id] = len(messages_result) if msg_status == 200 else 0
    
    return jsonify(unread_counts)

@app.route('/user/contact')
@login_required
def user_contact():
    # Get contact details (first record)
    contact_result, status = get_objects('ContactDetails', page_size=1)
    contact = contact_result[0] if status == 200 and contact_result else None
    
    # Get team members
    team_result, team_status = get_objects('TeamMembers')
    team_members = team_result if team_status == 200 else []
    
    return render_template('user.html', section='contact', contact=contact, team_members=team_members)

@app.route('/user/profile')
@login_required
def user_profile():
    # Get fresh user data from Backendless
    user_result, status = get_object_by_id('Users', current_user.id)
    if status == 200:
        current_user.profile_photo = user_result.get('profile_photo')
    return render_template('user.html', section='profile', user=current_user)

@app.route('/user/update-profile', methods=['POST'])
@login_required
def update_profile():
    if 'profile_photo' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('user_profile'))
    
    file = request.files['profile_photo']
    
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('user_profile'))
    
    if file and allowed_file(file.filename):
        # Upload to Backendless
        upload_result = upload_file_to_backendless(file, 'profile_photos')
        
        if upload_result.get('success'):
            filename = upload_result.get('filename')
            
            # Update user record in Backendless
            update_data = {'profile_photo': filename}
            result, status = update_object('Users', current_user.id, update_data)
            
            if status == 200:
                current_user.profile_photo = filename
                flash('Profile photo updated successfully!', 'success')
            else:
                flash('Failed to update profile in database', 'danger')
        else:
            flash('Failed to upload file', 'danger')
    else:
        flash('Invalid file type. Please upload an image (PNG, JPG, JPEG, GIF).', 'danger')
    
    return redirect(url_for('user_profile'))

@app.route('/user/change-password', methods=['POST'])
@login_required
def user_change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not check_password_hash(current_user.password, current_password):
        flash('Current password is incorrect', 'danger')
        return redirect(url_for('user_profile'))
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'danger')
        return redirect(url_for('user_profile'))
    
    if len(new_password) < 8:
        flash('New password must be at least 8 characters long', 'danger')
        return redirect(url_for('user_profile'))
    
    # Update password in Backendless
    update_data = {'password': generate_password_hash(new_password)}
    result, status = update_object('Users', current_user.id, update_data)
    
    if status == 200:
        flash('Password changed successfully!', 'success')
    else:
        flash('Failed to update password', 'danger')
    
    return redirect(url_for('user_profile'))

# ============================================================================
# ADMIN ROUTES
# ============================================================================

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    projects_result, status = get_objects('Projects', page_size=100)
    projects = projects_result if status == 200 else []
    
    total_projects = len(projects)
    accepted = len([p for p in projects if p.get('status') == 'Accepted'])
    rejected = len([p for p in projects if p.get('status') == 'Rejected'])
    in_progress = len([p for p in projects if p.get('status') == 'In Progress'])
    completed = len([p for p in projects if p.get('status') == 'Completed'])
    
    # Get unread message counts
    for project in projects:
        messages_result, msg_status = get_objects('Messages', 
            f"project_id = '{project.get('objectId')}' AND sender = 'user' AND is_read = false")
        project['unread_user_messages'] = len(messages_result) if msg_status == 200 else 0
    
    return render_template('admin.html',
                         section='dashboard',
                         total_projects=total_projects,
                         accepted=accepted,
                         rejected=rejected,
                         in_progress=in_progress,
                         completed=completed,
                         projects=projects)

@app.route('/admin/manage-projects')
@admin_required
def admin_manage_projects():
    projects_result, status = get_objects('Projects', page_size=100)
    projects = projects_result if status == 200 else []
    
    # Get message counts for each project
    for project in projects:
        messages_result, msg_status = get_objects('Messages', 
            f"project_id = '{project.get('objectId')}' AND sender = 'user' AND is_read = false")
        project['unread_user_messages'] = len(messages_result) if msg_status == 200 else 0
    
    return render_template('admin.html', section='manage_projects', projects=projects)

@app.route('/admin/update-project-status/<project_id>/<status>')
@admin_required
def update_project_status(project_id, status):
    project_result, proj_status = get_object_by_id('Projects', project_id)
    
    if proj_status != 200:
        flash('Project not found', 'danger')
        return redirect(url_for('admin_manage_projects'))
    
    old_status = project_result.get('status')
    
    # Update project status
    update_data = {'status': status}
    result, update_status = update_object('Projects', project_id, update_data)
    
    if update_status == 200:
        # Send automatic message about status change
        status_messages = {
            'Accepted': '✅ Your project has been accepted! We will start working on it soon.',
            'Rejected': '❌ Your project has been rejected. Please contact admin for more details.',
            'In Progress': '🔄 Good news! Your project is now in progress. Check tracking for updates.',
            'Completed': '🎉 Congratulations! Your project has been completed successfully.'
        }
        
        if status in status_messages and old_status != status:
            message_data = {
                'project_id': project_id,
                'sender': 'admin',
                'message': f"Project status changed from '{old_status}' to '{status}'. {status_messages.get(status, '')}",
                'timestamp': datetime.now().isoformat(),
                'is_read': False
            }
            create_object('Messages', message_data)
        
        flash(f'Project status updated to {status}', 'success')
    else:
        flash('Failed to update project status', 'danger')
    
    return redirect(url_for('admin_manage_projects'))

@app.route('/admin/update-tracking')
@admin_required
def admin_update_tracking():
    projects_result, status = get_objects('Projects', page_size=100)
    projects = projects_result if status == 200 else []
    
    # Calculate progress for each project
    for project in projects:
        tracking_result, track_status = get_objects('ProjectTracking', f"project_id = '{project.get('objectId')}'")
        if track_status == 200 and tracking_result:
            total_steps = len(tracking_result)
            completed_steps = len([s for s in tracking_result if s.get('step_status') == 'Completed'])
            project['progress'] = (completed_steps / total_steps * 100) if total_steps > 0 else 0
        else:
            project['progress'] = 0
    
    return render_template('admin.html', section='update_tracking', projects=projects)

@app.route('/admin/project/<project_id>/tracking')
@admin_required
def view_project_tracking_admin(project_id):
    project_result, status = get_object_by_id('Projects', project_id)
    
    if status != 200:
        flash('Project not found', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    tracking_result, track_status = get_objects('ProjectTracking', f"project_id = '{project_id}'")
    tracking_steps = tracking_result if track_status == 200 else []
    
    documents_result, doc_status = get_objects('ProjectDocuments', f"project_id = '{project_id}'")
    documents = documents_result if doc_status == 200 else []
    
    # Calculate progress
    total_steps = len(tracking_steps)
    completed_steps = len([s for s in tracking_steps if s.get('step_status') == 'Completed'])
    progress = (completed_steps / total_steps * 100) if total_steps > 0 else 0
    
    return render_template('admin.html', 
                         section='tracking_detail',
                         project=project_result,
                         tracking_steps=tracking_steps,
                         documents=documents,
                         progress=progress)

@app.route('/admin/add-tracking-step', methods=['POST'])
@admin_required
def add_tracking_step():
    project_id = request.form.get('project_id')
    step_name = request.form.get('step_name')
    
    if not project_id or not step_name:
        flash('Please provide step name', 'danger')
        return redirect(url_for('admin_update_tracking'))
    
    tracking_data = {
        'project_id': project_id,
        'step_name': step_name,
        'step_status': 'Pending',
        'created_at': datetime.now().isoformat()
    }
    
    result, status = create_object('ProjectTracking', tracking_data)
    
    if status == 200:
        # Notify user about new tracking step
        message_data = {
            'project_id': project_id,
            'sender': 'admin',
            'message': f"📋 New tracking step added: '{step_name}'. Check your project tracking for details.",
            'timestamp': datetime.now().isoformat(),
            'is_read': False
        }
        create_object('Messages', message_data)
        
        flash('Tracking step added successfully!', 'success')
    else:
        flash('Failed to add tracking step', 'danger')
    
    return redirect(url_for('view_project_tracking_admin', project_id=project_id))

@app.route('/admin/update-step-status/<step_id>', methods=['POST'])
@admin_required
def update_step_status(step_id):
    step_result, status = get_object_by_id('ProjectTracking', step_id)
    
    if status != 200:
        flash('Step not found', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    new_status = request.form.get('status')
    old_status = step_result.get('step_status')
    
    update_data = {'step_status': new_status}
    
    # Handle file uploads
    proof_filenames = []
    if 'proof_file' in request.files:
        files = request.files.getlist('proof_file')
        for file in files:
            if file and allowed_file(file.filename):
                upload_result = upload_file_to_backendless(file, 'project_documents')
                if upload_result.get('success'):
                    filename = upload_result.get('filename')
                    proof_filenames.append(filename)
                    
                    # Add to ProjectDocuments
                    doc_data = {
                        'project_id': step_result.get('project_id'),
                        'file_name': file.filename,
                        'file_path': filename,
                        'file_type': 'proof',
                        'uploaded_at': datetime.now().isoformat()
                    }
                    create_object('ProjectDocuments', doc_data)
    
    if proof_filenames:
        existing_files = step_result.get('proof_files', '')
        if existing_files:
            update_data['proof_files'] = existing_files + ',' + ','.join(proof_filenames)
        else:
            update_data['proof_files'] = ','.join(proof_filenames)
    
    image_filenames = []
    if 'images' in request.files:
        images = request.files.getlist('images')
        for image in images:
            if image and allowed_file(image.filename):
                upload_result = upload_file_to_backendless(image, 'project_documents')
                if upload_result.get('success'):
                    filename = upload_result.get('filename')
                    image_filenames.append(filename)
                    
                    # Add to ProjectDocuments
                    doc_data = {
                        'project_id': step_result.get('project_id'),
                        'file_name': image.filename,
                        'file_path': filename,
                        'file_type': 'image',
                        'uploaded_at': datetime.now().isoformat()
                    }
                    create_object('ProjectDocuments', doc_data)
    
    if image_filenames:
        existing_images = step_result.get('images', '')
        if existing_images:
            update_data['images'] = existing_images + ',' + ','.join(image_filenames)
        else:
            update_data['images'] = ','.join(image_filenames)
    
    update_data['updated_at'] = datetime.now().isoformat()
    
    result, update_status = update_object('ProjectTracking', step_id, update_data)
    
    if update_status == 200 and old_status != new_status:
        # Notify user about step status change
        status_icon = '✅' if new_status == 'Completed' else '⏳'
        message_data = {
            'project_id': step_result.get('project_id'),
            'sender': 'admin',
            'message': f"{status_icon} Tracking step '{step_result.get('step_name')}' is now {new_status}.",
            'timestamp': datetime.now().isoformat(),
            'is_read': False
        }
        create_object('Messages', message_data)
        
        flash('Step updated successfully!', 'success')
    elif update_status == 200:
        flash('Step updated successfully!', 'success')
    else:
        flash('Failed to update step', 'danger')
    
    return redirect(url_for('view_project_tracking_admin', project_id=step_result.get('project_id')))

@app.route('/admin/upload-documents')
@admin_required
def admin_upload_documents():
    projects_result, status = get_objects('Projects', page_size=100)
    projects = projects_result if status == 200 else []
    return render_template('admin.html', section='upload_documents', projects=projects)

@app.route('/admin/upload-project-document', methods=['POST'])
@admin_required
def upload_project_document():
    project_id = request.form.get('project_id')
    
    if not project_id:
        flash('Please select a project', 'danger')
        return redirect(url_for('admin_upload_documents'))
    
    if 'document' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('admin_upload_documents'))
    
    file = request.files['document']
    if file and allowed_file(file.filename):
        # Upload to Backendless
        upload_result = upload_file_to_backendless(file, 'project_documents')
        
        if upload_result.get('success'):
            filename = upload_result.get('filename')
            
            # Store in ProjectDocuments
            doc_data = {
                'project_id': project_id,
                'file_name': file.filename,
                'file_path': filename,
                'file_type': 'document',
                'uploaded_at': datetime.now().isoformat()
            }
            
            result, doc_status = create_object('ProjectDocuments', doc_data)
            
            if doc_status == 200:
                # Notify user about new document
                message_data = {
                    'project_id': project_id,
                    'sender': 'admin',
                    'message': f"📎 New document uploaded: '{file.filename}'. You can view it in the Summarize Documents section.",
                    'timestamp': datetime.now().isoformat(),
                    'is_read': False
                }
                create_object('Messages', message_data)
                
                flash('Document uploaded successfully!', 'success')
            else:
                flash('Failed to save document record', 'danger')
        else:
            flash('Failed to upload file', 'danger')
    else:
        flash('Invalid file type. Allowed: PDF, DOC, DOCX, TXT, images', 'danger')
    
    return redirect(url_for('admin_upload_documents'))

@app.route('/admin/fix-documents')
@admin_required
def fix_documents():
    # This function is less critical now with Backendless,
    # but we'll keep a simplified version for local file cleanup
    
    tracking_result, status = get_objects('ProjectTracking', page_size=100)
    tracking_steps = tracking_result if status == 200 else []
    
    fixed_count = 0
    project_files = {}
    
    # Check for files in tracking that aren't in ProjectDocuments
    for step in tracking_steps:
        project_id = step.get('project_id')
        if project_id not in project_files:
            project_files[project_id] = {
                'proof': [],
                'images': []
            }
        
        # Check proof files
        if step.get('proof_files'):
            files = step.get('proof_files').split(',')
            for filename in files:
                if filename and filename.strip():
                    # Check if exists in ProjectDocuments
                    docs_result, doc_status = get_objects('ProjectDocuments', f"file_path = '{filename}'")
                    if doc_status != 200 or not docs_result:
                        # Add missing document
                        doc_data = {
                            'project_id': project_id,
                            'file_name': filename.split('/')[-1],
                            'file_path': filename,
                            'file_type': 'proof',
                            'uploaded_at': step.get('updated_at') or datetime.now().isoformat()
                        }
                        create_object('ProjectDocuments', doc_data)
                        fixed_count += 1
                        project_files[project_id]['proof'].append(filename)
        
        # Check images
        if step.get('images'):
            images = step.get('images').split(',')
            for filename in images:
                if filename and filename.strip():
                    docs_result, doc_status = get_objects('ProjectDocuments', f"file_path = '{filename}'")
                    if doc_status != 200 or not docs_result:
                        doc_data = {
                            'project_id': project_id,
                            'file_name': filename.split('/')[-1],
                            'file_path': filename,
                            'file_type': 'image',
                            'uploaded_at': step.get('updated_at') or datetime.now().isoformat()
                        }
                        create_object('ProjectDocuments', doc_data)
                        fixed_count += 1
                        project_files[project_id]['images'].append(filename)
    
    if fixed_count > 0:
        flash(f'✅ Fixed {fixed_count} missing documents in Backendless!', 'success')
    else:
        flash('No missing documents found.', 'info')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/messages')
@admin_required
def admin_messages():
    projects_result, status = get_objects('Projects', page_size=100)
    projects = projects_result if status == 200 else []
    
    messages_dict = {}
    unread_counts = {}
    
    for project in projects:
        project_id = project.get('objectId')
        # Get all messages for this project
        messages_result, msg_status = get_objects('Messages', f"project_id = '{project_id}'", page_size=100)
        
        if msg_status == 200 and messages_result:
            # Sort by timestamp
            sorted_messages = sorted(messages_result, key=lambda x: x.get('timestamp', ''))
            messages_dict[project_id] = sorted_messages
        
        # Count unread user messages
        unread_result, unread_status = get_objects('Messages', 
            f"project_id = '{project_id}' AND sender = 'user' AND is_read = false")
        unread_counts[project_id] = len(unread_result) if unread_status == 200 else 0
    
    return render_template('admin.html', 
                         section='messages', 
                         messages=messages_dict,
                         unread_counts=unread_counts,
                         projects=projects)

@app.route('/admin/send-reply', methods=['POST'])
@admin_required
def send_reply():
    project_id = request.form.get('project_id')
    message_text = request.form.get('message')
    
    if not project_id or not message_text:
        return jsonify({'success': False, 'error': 'Missing data'})
    
    message_data = {
        'project_id': project_id,
        'sender': 'admin',
        'message': message_text,
        'timestamp': datetime.now().isoformat(),
        'is_read': False
    }
    
    result, status = create_object('Messages', message_data)
    
    if status == 200:
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Failed to send message'})

@app.route('/admin/mark-messages-read/<project_id>', methods=['POST'])
@admin_required
def admin_mark_messages_read(project_id):
    # Get all unread user messages
    messages_result, msg_status = get_objects('Messages', 
        f"project_id = '{project_id}' AND sender = 'user' AND is_read = false")
    
    if msg_status == 200 and messages_result:
        for message in messages_result:
            update_object('Messages', message.get('objectId'), {'is_read': True})
    
    return jsonify({'success': True})

@app.route('/admin/get-unread-counts')
@admin_required
def admin_get_unread_counts():
    projects_result, status = get_objects('Projects', page_size=100)
    projects = projects_result if status == 200 else []
    
    unread_counts = {}
    
    for project in projects:
        project_id = project.get('objectId')
        messages_result, msg_status = get_objects('Messages', 
            f"project_id = '{project_id}' AND sender = 'user' AND is_read = false")
        unread_counts[project_id] = len(messages_result) if msg_status == 200 else 0
    
    return jsonify(unread_counts)

@app.route('/admin/contact-details')
@admin_required
def admin_contact_details():
    # Get contact details (first record)
    contact_result, status = get_objects('ContactDetails', page_size=1)
    contact = contact_result[0] if status == 200 and contact_result else None
    
    # Get team members
    team_result, team_status = get_objects('TeamMembers')
    team_members = team_result if team_status == 200 else []
    
    return render_template('admin.html', section='contact_details', contact=contact, team_members=team_members)

# ============================================================================
# TEAM MEMBER MANAGEMENT ROUTES
# ============================================================================

@app.route('/admin/add-team-member', methods=['POST'])
@admin_required
def add_team_member():
    name = request.form.get('name')
    role = request.form.get('role')
    email = request.form.get('email')
    mobile = request.form.get('mobile')
    
    if not all([name, role, email, mobile]):
        flash('All fields are required', 'danger')
        return redirect(url_for('admin_contact_details'))
    
    # Handle photo upload
    photo_filename = None
    if 'photo' in request.files:
        file = request.files['photo']
        if file and file.filename and allowed_file(file.filename):
            upload_result = upload_file_to_backendless(file, 'team_photos')
            if upload_result.get('success'):
                photo_filename = upload_result.get('filename')
    
    # Create new team member
    member_data = {
        'name': name,
        'role': role,
        'email': email,
        'mobile': mobile,
        'photo': photo_filename,
        'created_at': datetime.now().isoformat()
    }
    
    result, status = create_object('TeamMembers', member_data)
    
    if status == 200:
        flash(f'Team member {name} added successfully!', 'success')
    else:
        flash('Failed to add team member', 'danger')
    
    return redirect(url_for('admin_contact_details'))

@app.route('/admin/edit-team-member/<member_id>', methods=['POST'])
@admin_required
def edit_team_member(member_id):
    member_result, status = get_object_by_id('TeamMembers', member_id)
    
    if status != 200:
        flash('Team member not found', 'danger')
        return redirect(url_for('admin_contact_details'))
    
    update_data = {
        'name': request.form.get('name', member_result.get('name')),
        'role': request.form.get('role', member_result.get('role')),
        'email': request.form.get('email', member_result.get('email')),
        'mobile': request.form.get('mobile', member_result.get('mobile'))
    }
    
    # Handle photo upload
    if 'photo' in request.files:
        file = request.files['photo']
        if file and file.filename and allowed_file(file.filename):
            upload_result = upload_file_to_backendless(file, 'team_photos')
            if upload_result.get('success'):
                update_data['photo'] = upload_result.get('filename')
                
                # Delete old photo if exists locally
                if member_result.get('photo'):
                    old_path = os.path.join(app.config['UPLOAD_FOLDER'], 'team_photos', member_result.get('photo'))
                    if os.path.exists(old_path):
                        os.remove(old_path)
    
    result, update_status = update_object('TeamMembers', member_id, update_data)
    
    if update_status == 200:
        flash(f'Team member updated successfully!', 'success')
    else:
        flash('Failed to update team member', 'danger')
    
    return redirect(url_for('admin_contact_details'))

@app.route('/admin/delete-team-member/<member_id>', methods=['POST'])
@admin_required
def delete_team_member(member_id):
    member_result, status = get_object_by_id('TeamMembers', member_id)
    
    if status == 200 and member_result.get('photo'):
        # Delete photo if exists locally
        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], 'team_photos', member_result.get('photo'))
        if os.path.exists(photo_path):
            os.remove(photo_path)
    
    result, delete_status = delete_object('TeamMembers', member_id)
    
    if delete_status == 200:
        flash(f'Team member deleted successfully!', 'success')
    else:
        flash('Failed to delete team member', 'danger')
    
    return redirect(url_for('admin_contact_details'))

@app.route('/admin/get-team-member/<member_id>')
@admin_required
def get_team_member(member_id):
    member_result, status = get_object_by_id('TeamMembers', member_id)
    
    if status == 200:
        return jsonify({
            'id': member_id,
            'name': member_result.get('name'),
            'role': member_result.get('role'),
            'email': member_result.get('email'),
            'mobile': member_result.get('mobile'),
            'photo': member_result.get('photo')
        })
    else:
        return jsonify({'error': 'Member not found'}), 404

@app.route('/admin/update-contact', methods=['POST'])
@admin_required
def update_contact():
    email = request.form.get('email')
    phone = request.form.get('phone')
    address = request.form.get('address')
    
    # Get existing contact
    contact_result, status = get_objects('ContactDetails', page_size=1)
    
    contact_data = {
        'email': email,
        'phone': phone,
        'address': address
    }
    
    if status == 200 and contact_result:
        # Update existing
        contact_id = contact_result[0].get('objectId')
        result, update_status = update_object('ContactDetails', contact_id, contact_data)
    else:
        # Create new
        result, update_status = create_object('ContactDetails', contact_data)
    
    if update_status == 200:
        flash('Contact details updated successfully!', 'success')
    else:
        flash('Failed to update contact details', 'danger')
    
    return redirect(url_for('admin_contact_details'))

# ============================================================================
# DEBUG ROUTES
# ============================================================================

@app.route('/debug/documents')
@admin_required
def debug_documents():
    """Debug route to check documents"""
    docs_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'project_documents')
    files = []
    if os.path.exists(docs_dir):
        files = os.listdir(docs_dir)
    
    documents_result, status = get_objects('ProjectDocuments', page_size=100)
    documents = documents_result if status == 200 else []
    
    doc_info = []
    for doc in documents:
        file_exists = os.path.exists(os.path.join(docs_dir, doc.get('file_path', ''))) if doc.get('file_path') else False
        doc_info.append({
            'id': doc.get('objectId'),
            'file_name': doc.get('file_name'),
            'file_path': doc.get('file_path'),
            'project_id': doc.get('project_id'),
            'file_type': doc.get('file_type'),
            'uploaded_at': doc.get('uploaded_at'),
            'file_exists': file_exists,
            'url': url_for('project_document', filename=doc.get('file_path')) if doc.get('file_path') else None
        })
    
    result = {
        'documents_in_backendless': len(documents),
        'files_in_directory': len(files),
        'directory': docs_dir,
        'documents': doc_info,
        'files': files
    }
    
    return jsonify(result)

@app.route('/debug/profile-photos')
@login_required
def debug_profile_photos():
    """Debug route to check profile photos"""
    photos_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_photos')
    files = []
    if os.path.exists(photos_dir):
        files = os.listdir(photos_dir)
    
    result = {
        'user_id': current_user.id,
        'username': current_user.username,
        'profile_photo_filename': current_user.profile_photo,
        'files_in_directory': files,
        'upload_folder': app.config['UPLOAD_FOLDER'],
        'profile_photos_dir': photos_dir,
        'file_exists': os.path.exists(os.path.join(photos_dir, current_user.profile_photo)) if current_user.profile_photo else False,
        'photo_url': url_for('profile_photo', filename=current_user.profile_photo) if current_user.profile_photo else None
    }
    
    return jsonify(result)

# ============================================================================
# INITIALIZATION
# ============================================================================

def initialize_backendless_tables():
    """Create default data in Backendless if needed"""
    
    # Check if contact details exist
    contact_result, status = get_objects('ContactDetails', page_size=1)
    if status != 200 or not contact_result:
        # Create default contact
        default_contact = {
            'email': 'admin@example.com',
            'phone': '+1234567890',
            'address': '123 Main Street, City, Country'
        }
        create_object('ContactDetails', default_contact)
        print("✅ Created default contact details")
    
    print("📊 Backendless initialization complete")

if __name__ == '__main__':
    try:
        contact_list = backendless_get_all('ContactDetails') or []

        if not contact_list:
            default_contact = {
                'email': 'admin@example.com',
                'phone': '+1234567890',
                'address': '123 Main Street, City, Country'
            }
            backendless_create('ContactDetails', default_contact)
            print("✅ Created default contact details")

    except Exception as e:
        print("⚠️ ContactDetails table not found. Please create it in Backendless.")

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
