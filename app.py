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
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import OperationalError
from fpdf import FPDF
import PyPDF2
import os
import tempfile

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///project_management.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# OpenRouter AI Configuration
app.config['OPENROUTER_API_KEY'] = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' 
app.config['OPENROUTER_API_URL'] = 'https://openrouter.ai/api/v1/chat/completions'
app.config['OPENROUTER_MODEL'] = 'openai/gpt-3.5-turbo'  # You can change this model

# Email configuration for OTP (Update with your email credentials)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'girivennapusa8@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'XXXXXXXXXXXXXX'  # Replace with your app password
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@gmail.com'


# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'profile_photos'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'project_documents'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'team_photos'), exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'base'

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    mobile = db.Column(db.String(20))
    password = db.Column(db.String(200), nullable=False)
    profile_photo = db.Column(db.String(200))  # Store only filename
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    projects = db.relationship('Project', backref='user', lazy=True, cascade='all, delete-orphan')

class Project(db.Model):
    __tablename__ = 'projects'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(50), default='Requested')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tracking_steps = db.relationship('ProjectTracking', backref='project', lazy=True, cascade='all, delete-orphan')
    documents = db.relationship('ProjectDocument', backref='project', lazy=True, cascade='all, delete-orphan')
    messages = db.relationship('Message', backref='project', lazy=True, cascade='all, delete-orphan', order_by='Message.timestamp')

class ProjectTracking(db.Model):
    __tablename__ = 'project_tracking'
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    step_name = db.Column(db.String(200), nullable=False)
    step_status = db.Column(db.String(50), default='Pending')
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    proof_files = db.Column(db.Text)  # Store as comma-separated filenames
    images = db.Column(db.Text)  # Store as comma-separated filenames

class ProjectDocument(db.Model):
    __tablename__ = 'project_documents'
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    file_name = db.Column(db.String(200))
    file_path = db.Column(db.String(200))  # Store only filename, not full path
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    file_type = db.Column(db.String(50), default='document')  # 'proof', 'image', or 'document'
    ai_summary = db.Column(db.Text, nullable=True)  # Store AI-generated summary
    key_points = db.Column(db.Text, nullable=True)  # Store extracted key points
    tools_technologies = db.Column(db.Text, nullable=True)  # Store extracted tools and technologies
    technical_jargon = db.Column(db.Text, nullable=True)  # Store technical jargon

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    sender = db.Column(db.String(50))  # 'user' or 'admin'
    message = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)  # Track if message has been read

class ContactDetails(db.Model):
    __tablename__ = 'contact_details'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    address = db.Column(db.Text)

# Team Member Model
class TeamMember(db.Model):
    __tablename__ = 'team_members'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    mobile = db.Column(db.String(20), nullable=False)
    photo = db.Column(db.String(200))  # Store filename
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# OTP Storage
otp_storage = {}  # Format: {email: {'otp': '123456', 'timestamp': 1234567890}}

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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Admin access required', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Database migration function
def add_missing_columns():
    """Add missing columns to tables if they don't exist"""
    inspector = inspect(db.engine)
    
    # Check users table
    if 'users' in inspector.get_table_names():
        user_columns = [col['name'] for col in inspector.get_columns('users')]
        
        # Add created_at column if it doesn't exist
        if 'created_at' not in user_columns:
            print("📝 Adding created_at column to users table...")
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE users ADD COLUMN created_at TIMESTAMP"))
                    conn.commit()
                print("✅ Successfully added created_at column to users table")
            except Exception as e:
                print(f"❌ Failed to add created_at column: {str(e)}")
    
    # Check project_documents table
    if 'project_documents' in inspector.get_table_names():
        doc_columns = [col['name'] for col in inspector.get_columns('project_documents')]
        
        if 'file_type' not in doc_columns:
            print("📝 Adding file_type column to project_documents table...")
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE project_documents ADD COLUMN file_type VARCHAR(50) DEFAULT 'document'"))
                    conn.commit()
                print("✅ Successfully added file_type column")
            except Exception as e:
                print(f"❌ Failed to add file_type column: {str(e)}")
        
        # Add AI summary columns if they don't exist
        if 'ai_summary' not in doc_columns:
            print("📝 Adding ai_summary column to project_documents table...")
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE project_documents ADD COLUMN ai_summary TEXT"))
                    conn.commit()
                print("✅ Successfully added ai_summary column")
            except Exception as e:
                print(f"❌ Failed to add ai_summary column: {str(e)}")
        
        if 'key_points' not in doc_columns:
            print("📝 Adding key_points column to project_documents table...")
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE project_documents ADD COLUMN key_points TEXT"))
                    conn.commit()
                print("✅ Successfully added key_points column")
            except Exception as e:
                print(f"❌ Failed to add key_points column: {str(e)}")
        
        if 'tools_technologies' not in doc_columns:
            print("📝 Adding tools_technologies column to project_documents table...")
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE project_documents ADD COLUMN tools_technologies TEXT"))
                    conn.commit()
                print("✅ Successfully added tools_technologies column")
            except Exception as e:
                print(f"❌ Failed to add tools_technologies column: {str(e)}")
        
        if 'technical_jargon' not in doc_columns:
            print("📝 Adding technical_jargon column to project_documents table...")
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE project_documents ADD COLUMN technical_jargon TEXT"))
                    conn.commit()
                print("✅ Successfully added technical_jargon column")
            except Exception as e:
                print(f"❌ Failed to add technical_jargon column: {str(e)}")

# Routes
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
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('base'))
        
        if User.query.filter_by(email=email).first():
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
        
        # Create user
        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username, 
            email=email, 
            mobile=mobile, 
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        
        # Clear OTP
        otp_storage.pop(email, None)
        
        flash('Registration successful! Please login.', 'success')
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
        
        # Check if email already registered
        if User.query.filter_by(email=email).first():
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
    
    user = User.query.filter(
        (User.username == username_or_email) | (User.email == username_or_email)
    ).first()
    
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

# File serving routes
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    """Serve files from the uploads directory"""
    try:
        # Security check to prevent directory traversal
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
        # Security check
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
        # Security check
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
        # Security check
        if '..' in filename or filename.startswith('/'):
            abort(404)
        return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], 'team_photos'), filename)
    except Exception as e:
        print(f"Error serving team photo {filename}: {str(e)}")
        return "File not found", 404

# User Routes
@app.route('/user/dashboard')
@login_required
def user_dashboard():
    projects = Project.query.filter_by(user_id=current_user.id).all()
    total_projects = len(projects)
    accepted = len([p for p in projects if p.status == 'Accepted'])
    rejected = len([p for p in projects if p.status == 'Rejected'])
    in_progress = len([p for p in projects if p.status == 'In Progress'])
    
    # Get unread message count for each project
    for project in projects:
        project.unread_count = Message.query.filter_by(
            project_id=project.id, 
            sender='admin', 
            is_read=False
        ).count()
    
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
    projects = Project.query.filter_by(user_id=current_user.id).all()
    return render_template('user.html', section='projects', projects=projects)

@app.route('/user/request-project', methods=['POST'])
@login_required
def request_project():
    title = request.form.get('title')
    description = request.form.get('description')
    
    if not title or not description:
        flash('Please provide both title and description', 'danger')
        return redirect(url_for('user_projects'))
    
    new_project = Project(user_id=current_user.id, title=title, description=description)
    db.session.add(new_project)
    db.session.commit()
    
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
        tracking = ProjectTracking(project_id=new_project.id, step_name=step)
        db.session.add(tracking)
    
    db.session.commit()
    
    # Send welcome message
    welcome_message = Message(
        project_id=new_project.id,
        sender='admin',
        message="✅ Welcome! Your project has been created successfully. We'll review your request and get back to you soon."
    )
    db.session.add(welcome_message)
    db.session.commit()
    
    flash('Project requested successfully!', 'success')
    return redirect(url_for('user_projects'))

@app.route('/user/track-projects')
@login_required
def user_track_projects():
    projects = Project.query.filter_by(user_id=current_user.id).all()
    
    # Calculate progress for each project
    for project in projects:
        total_steps = len(project.tracking_steps)
        completed_steps = len([s for s in project.tracking_steps if s.step_status == 'Completed'])
        project.progress = (completed_steps / total_steps * 100) if total_steps > 0 else 0
    
    return render_template('user.html', section='track', projects=projects)

@app.route('/user/project/<int:project_id>/track')
@login_required
def view_project_tracking(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('user_dashboard'))
    
    tracking_steps = ProjectTracking.query.filter_by(project_id=project_id).all()
    documents = ProjectDocument.query.filter_by(project_id=project_id).all()
    
    # Calculate progress
    total_steps = len(tracking_steps)
    completed_steps = len([s for s in tracking_steps if s.step_status == 'Completed'])
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
    projects = Project.query.filter_by(user_id=current_user.id).all()
    
    # Debug print
    print(f"User {current_user.username} has {len(projects)} projects")
    for project in projects:
        print(f"Project {project.id}: {project.title} has {len(project.documents)} documents")
        for doc in project.documents:
            print(f"  - Document: {doc.file_name} (Type: {doc.file_type})")
    
    return render_template('user.html', 
                         section='summarize', 
                         projects=projects)

@app.route('/user/project/<int:project_id>/documents')
@login_required
def view_project_documents(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('user_dashboard'))
    
    documents = ProjectDocument.query.filter_by(project_id=project_id).all()
    
    # Debug print
    print(f"Project {project_id} has {len(documents)} documents")
    for doc in documents:
        print(f"Document: {doc.file_name}, Path: {doc.file_path}, Type: {doc.file_type}, Uploaded: {doc.uploaded_at}")
    
    return render_template('user.html', 
                         section='documents',
                         project=project,
                         documents=documents)

@app.route('/user/document/<int:doc_id>/summarize')
@login_required
def summarize_document(doc_id):
    document = ProjectDocument.query.get_or_404(doc_id)
    project = Project.query.get(document.project_id)
    
    if project.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('user_dashboard'))
    
    # Check if we already have an AI summary
    if document.ai_summary and document.key_points and document.tools_technologies:
        # Parse stored data
        try:
            key_points = json.loads(document.key_points) if document.key_points else []
            tools_technologies = json.loads(document.tools_technologies) if document.tools_technologies else []
            technical_jargon = json.loads(document.technical_jargon) if document.technical_jargon else []
            summary = document.ai_summary
        except:
            key_points = []
            tools_technologies = []
            technical_jargon = []
            summary = document.ai_summary
    else:
        # Extract text and generate AI summary
        full_text = extract_text_from_file(document.file_path, document.file_name)
        
        if full_text and not full_text.startswith(("Preview not available", "File not found", "Error reading")):
            ai_result = summarize_with_openrouter(full_text)
            
            # Store results in database
            document.ai_summary = ai_result['summary']
            document.key_points = json.dumps(ai_result['key_points'])
            document.tools_technologies = json.dumps(ai_result['tools_technologies'])
            document.technical_jargon = json.dumps(ai_result.get('technical_jargon', []))
            
            db.session.commit()
            
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
    messages = Message.query.filter_by(project_id=project.id).order_by(Message.timestamp).all()
    
    # Get full text for display
    full_text = extract_text_from_file(document.file_path, document.file_name)
    
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

@app.route('/user/regenerate-summary/<int:doc_id>', methods=['POST'])
@login_required
def regenerate_summary(doc_id):
    document = ProjectDocument.query.get_or_404(doc_id)
    project = Project.query.get(document.project_id)
    
    if project.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Unauthorized'})
    
    # Extract text and regenerate AI summary
    full_text = extract_text_from_file(document.file_path, document.file_name)
    
    if full_text and not full_text.startswith(("Preview not available", "File not found", "Error reading")):
        ai_result = summarize_with_openrouter(full_text)
        
        # Store results in database
        document.ai_summary = ai_result['summary']
        document.key_points = json.dumps(ai_result['key_points'])
        document.tools_technologies = json.dumps(ai_result['tools_technologies'])
        document.technical_jargon = json.dumps(ai_result.get('technical_jargon', []))
        
        db.session.commit()
        
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

# FIXED: Download summary as PDF with proper Unicode handling
@app.route('/user/download-summary/<int:doc_id>')
@login_required
def download_summary_pdf(doc_id):
    document = ProjectDocument.query.get_or_404(doc_id)
    project = Project.query.get(document.project_id)
    
    if project.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('user_dashboard'))
    
    # Get the summary data
    if document.ai_summary and document.key_points and document.tools_technologies:
        try:
            key_points = json.loads(document.key_points) if document.key_points else []
            tools_technologies = json.loads(document.tools_technologies) if document.tools_technologies else []
            technical_jargon = json.loads(document.technical_jargon) if document.technical_jargon else []
            summary = document.ai_summary
        except:
            key_points = []
            tools_technologies = []
            technical_jargon = []
            summary = document.ai_summary
    else:
        # If no AI summary exists, generate it
        full_text = extract_text_from_file(document.file_path, document.file_name)
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
    safe_file_name = clean_text_for_pdf(document.file_name)
    pdf.cell(200, 10, f"Document: {safe_file_name}", ln=True)
    
    pdf.set_font("Helvetica", "", 10)
    safe_project_title = clean_text_for_pdf(project.title)
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
            # Replace any remaining bullet points
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
    safe_filename = secure_filename(document.file_name).replace('.', '_')
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
    
    project = Project.query.get(project_id)
    if not project or project.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Unauthorized'})
    
    message = Message(project_id=project_id, sender='user', message=message_text)
    db.session.add(message)
    db.session.commit()
    
    return jsonify({
        'success': True, 
        'message': message_text, 
        'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M')
    })

@app.route('/user/chat')
@login_required
def user_chat():
    projects = Project.query.filter_by(user_id=current_user.id).all()
    messages_dict = {}
    unread_counts = {}
    
    print(f"Loading chat for user {current_user.username}")  # Debug
    print(f"Found {len(projects)} projects")  # Debug
    
    for project in projects:
        # Get all messages for this project ordered by timestamp
        project_messages = Message.query.filter_by(project_id=project.id).order_by(Message.timestamp).all()
        print(f"Project {project.id} ({project.title}) has {len(project_messages)} messages")  # Debug
        
        if project_messages:
            messages_dict[project] = project_messages
        
        # Count unread admin messages
        unread_counts[project.id] = Message.query.filter_by(
            project_id=project.id, 
            sender='admin', 
            is_read=False
        ).count()
    
    print(f"Messages dict has {len(messages_dict)} projects with messages")  # Debug
    print(f"Unread counts: {unread_counts}")  # Debug
    
    return render_template('user.html', 
                         section='chat', 
                         projects=projects,
                         messages=messages_dict,
                         unread_counts=unread_counts)

@app.route('/user/mark-messages-read/<int:project_id>', methods=['POST'])
@login_required
def mark_messages_read(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Unauthorized'})
    
    # Mark all admin messages as read
    Message.query.filter_by(project_id=project_id, sender='admin', is_read=False).update({'is_read': True})
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/user/get-unread-counts')
@login_required
def user_get_unread_counts():
    projects = Project.query.filter_by(user_id=current_user.id).all()
    unread_counts = {}
    
    for project in projects:
        unread_counts[project.id] = Message.query.filter_by(
            project_id=project.id, 
            sender='admin', 
            is_read=False
        ).count()
    
    return jsonify(unread_counts)

@app.route('/user/contact')
@login_required
def user_contact():
    contact = ContactDetails.query.first()
    team_members = TeamMember.query.all()  # Get all team members
    return render_template('user.html', section='contact', contact=contact, team_members=team_members)

@app.route('/user/profile')
@login_required
def user_profile():
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
        # Create a unique filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        # Clean filename and ensure it's secure
        safe_filename = secure_filename(file.filename)
        filename = f"profile_{current_user.id}_{timestamp}_{safe_filename}"
        
        # Save to profile_photos subdirectory
        profile_photos_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_photos')
        full_path = os.path.join(profile_photos_dir, filename)
        
        # Ensure directory exists
        os.makedirs(profile_photos_dir, exist_ok=True)
        
        # Save the file
        file.save(full_path)
        
        # Store ONLY the filename in the database
        current_user.profile_photo = filename
        db.session.commit()
        
        print(f"✅ Profile photo saved: {filename}")
        print(f"✅ Full path: {full_path}")
        print(f"✅ File exists: {os.path.exists(full_path)}")
        
        flash('Profile photo updated successfully!', 'success')
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
    
    current_user.password = generate_password_hash(new_password)
    db.session.commit()
    flash('Password changed successfully!', 'success')
    return redirect(url_for('user_profile'))

# Admin Routes
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    projects = Project.query.all()
    total_projects = len(projects)
    accepted = len([p for p in projects if p.status == 'Accepted'])
    rejected = len([p for p in projects if p.status == 'Rejected'])
    in_progress = len([p for p in projects if p.status == 'In Progress'])
    completed = len([p for p in projects if p.status == 'Completed'])
    
    # Get unread message counts
    for project in projects:
        project.unread_user_messages = Message.query.filter_by(
            project_id=project.id, 
            sender='user', 
            is_read=False
        ).count()
    
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
    projects = Project.query.all()
    
    # Get message counts for each project
    for project in projects:
        project.unread_user_messages = Message.query.filter_by(
            project_id=project.id, 
            sender='user', 
            is_read=False
        ).count()
    
    return render_template('admin.html', section='manage_projects', projects=projects)

@app.route('/admin/update-project-status/<int:project_id>/<status>')
@admin_required
def update_project_status(project_id, status):
    project = Project.query.get_or_404(project_id)
    old_status = project.status
    project.status = status
    db.session.commit()
    
    # Send automatic message about status change
    status_messages = {
        'Accepted': '✅ Your project has been accepted! We will start working on it soon.',
        'Rejected': '❌ Your project has been rejected. Please contact admin for more details.',
        'In Progress': '🔄 Good news! Your project is now in progress. Check tracking for updates.',
        'Completed': '🎉 Congratulations! Your project has been completed successfully.'
    }
    
    if status in status_messages and old_status != status:
        auto_message = Message(
            project_id=project_id,
            sender='admin',
            message=f"Project status changed from '{old_status}' to '{status}'. {status_messages.get(status, '')}"
        )
        db.session.add(auto_message)
        db.session.commit()
    
    flash(f'Project status updated to {status}', 'success')
    return redirect(url_for('admin_manage_projects'))

@app.route('/admin/update-tracking')
@admin_required
def admin_update_tracking():
    projects = Project.query.all()
    
    # Calculate progress for each project
    for project in projects:
        total_steps = len(project.tracking_steps)
        completed_steps = len([s for s in project.tracking_steps if s.step_status == 'Completed'])
        project.progress = (completed_steps / total_steps * 100) if total_steps > 0 else 0
    
    return render_template('admin.html', section='update_tracking', projects=projects)

@app.route('/admin/project/<int:project_id>/tracking')
@admin_required
def view_project_tracking_admin(project_id):
    project = Project.query.get_or_404(project_id)
    tracking_steps = ProjectTracking.query.filter_by(project_id=project_id).all()
    documents = ProjectDocument.query.filter_by(project_id=project_id).all()
    
    # Calculate progress
    total_steps = len(tracking_steps)
    completed_steps = len([s for s in tracking_steps if s.step_status == 'Completed'])
    progress = (completed_steps / total_steps * 100) if total_steps > 0 else 0
    
    return render_template('admin.html', 
                         section='tracking_detail',
                         project=project,
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
    
    tracking = ProjectTracking(project_id=project_id, step_name=step_name)
    db.session.add(tracking)
    db.session.commit()
    
    # Notify user about new tracking step
    message = Message(
        project_id=project_id,
        sender='admin',
        message=f"📋 New tracking step added: '{step_name}'. Check your project tracking for details."
    )
    db.session.add(message)
    db.session.commit()
    
    flash('Tracking step added successfully!', 'success')
    return redirect(url_for('view_project_tracking_admin', project_id=project_id))

@app.route('/admin/update-step-status/<int:step_id>', methods=['POST'])
@admin_required
def update_step_status(step_id):
    step = ProjectTracking.query.get_or_404(step_id)
    status = request.form.get('status')
    old_status = step.step_status
    step.step_status = status
    
    # Handle file uploads
    if 'proof_file' in request.files:
        files = request.files.getlist('proof_file')
        proof_filenames = []
        for file in files:
            if file and allowed_file(file.filename):
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = secure_filename(f"proof_{step_id}_{timestamp}_{file.filename}")
                
                # Save to project_documents directory
                project_docs_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'project_documents')
                full_path = os.path.join(project_docs_dir, filename)
                file.save(full_path)
                
                proof_filenames.append(filename)
                
                # Also add to ProjectDocument table with just filename
                document = ProjectDocument(
                    project_id=step.project_id,
                    file_name=file.filename,
                    file_path=filename,  # Store only filename
                    file_type='proof',
                    uploaded_at=datetime.utcnow()
                )
                db.session.add(document)
                print(f"✅ Added proof file: {filename}")
        
        if proof_filenames:
            if step.proof_files:
                step.proof_files = step.proof_files + ',' + ','.join(proof_filenames)
            else:
                step.proof_files = ','.join(proof_filenames)
    
    if 'images' in request.files:
        images = request.files.getlist('images')
        image_filenames = []
        for image in images:
            if image and allowed_file(image.filename):
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = secure_filename(f"image_{step_id}_{timestamp}_{image.filename}")
                
                # Save to project_documents directory
                project_docs_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'project_documents')
                full_path = os.path.join(project_docs_dir, filename)
                image.save(full_path)
                
                image_filenames.append(filename)
                
                # Also add to ProjectDocument table with just filename
                document = ProjectDocument(
                    project_id=step.project_id,
                    file_name=image.filename,
                    file_path=filename,  # Store only filename
                    file_type='image',
                    uploaded_at=datetime.utcnow()
                )
                db.session.add(document)
                print(f"✅ Added image: {filename}")
        
        if image_filenames:
            if step.images:
                step.images = step.images + ',' + ','.join(image_filenames)
            else:
                step.images = ','.join(image_filenames)
    
    step.updated_at = datetime.utcnow()
    db.session.commit()
    
    # Notify user about step status change
    if old_status != status:
        status_icon = '✅' if status == 'Completed' else '⏳'
        message = Message(
            project_id=step.project_id,
            sender='admin',
            message=f"{status_icon} Tracking step '{step.step_name}' is now {status}."
        )
        db.session.add(message)
        db.session.commit()
    
    flash('Step updated successfully!', 'success')
    return redirect(url_for('view_project_tracking_admin', project_id=step.project_id))

@app.route('/admin/upload-documents')
@admin_required
def admin_upload_documents():
    projects = Project.query.all()
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
        # Create a unique filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = secure_filename(f"doc_{project_id}_{timestamp}_{file.filename}")
        
        # Save file to project_documents directory
        project_docs_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'project_documents')
        full_path = os.path.join(project_docs_dir, filename)
        file.save(full_path)
        
        # Store ONLY the filename in database
        document = ProjectDocument(
            project_id=project_id, 
            file_name=file.filename, 
            file_path=filename,  # Store only filename, not full path
            file_type='document',
            uploaded_at=datetime.utcnow()
        )
        db.session.add(document)
        db.session.commit()
        
        # Verify the document was saved
        saved_doc = ProjectDocument.query.get(document.id)
        print(f"✅ Document saved: ID={saved_doc.id}, Name={saved_doc.file_name}, Filename={saved_doc.file_path}")
        
        # Notify user about new document
        message = Message(
            project_id=project_id,
            sender='admin',
            message=f"📎 New document uploaded: '{file.filename}'. You can view it in the Summarize Documents section."
        )
        db.session.add(message)
        db.session.commit()
        
        flash('Document uploaded successfully!', 'success')
    else:
        flash('Invalid file type. Allowed: PDF, DOC, DOCX, TXT, images', 'danger')
    
    return redirect(url_for('admin_upload_documents'))

@app.route('/admin/fix-documents')
@admin_required
def fix_documents():
    # Find all tracking steps with proof files or images
    tracking_steps = ProjectTracking.query.all()
    fixed_count = 0
    project_files = {}
    
    for step in tracking_steps:
        project_id = step.project_id
        if project_id not in project_files:
            project_files[project_id] = {
                'proof': [],
                'images': []
            }
        
        # Fix proof files
        if step.proof_files:
            files = step.proof_files.split(',')
            for filename in files:
                if filename and filename.strip():  # Check if not empty
                    # Check if this file already exists in ProjectDocument
                    existing = ProjectDocument.query.filter_by(file_path=filename).first()
                    if not existing:
                        # Extract original filename (might be in path format)
                        original_filename = filename.split('/')[-1] if '/' in filename else filename
                        doc = ProjectDocument(
                            project_id=step.project_id,
                            file_name=original_filename,
                            file_path=original_filename,  # Store only filename
                            file_type='proof',
                            uploaded_at=step.updated_at or datetime.utcnow()
                        )
                        db.session.add(doc)
                        fixed_count += 1
                        project_files[project_id]['proof'].append(original_filename)
                        print(f"✅ Added missing proof file: {original_filename} for project {project_id}")
        
        # Fix images
        if step.images:
            images = step.images.split(',')
            for filename in images:
                if filename and filename.strip():  # Check if not empty
                    # Check if this image already exists in ProjectDocument
                    existing = ProjectDocument.query.filter_by(file_path=filename).first()
                    if not existing:
                        # Extract original filename
                        original_filename = filename.split('/')[-1] if '/' in filename else filename
                        doc = ProjectDocument(
                            project_id=step.project_id,
                            file_name=original_filename,
                            file_path=original_filename,  # Store only filename
                            file_type='image',
                            uploaded_at=step.updated_at or datetime.utcnow()
                        )
                        db.session.add(doc)
                        fixed_count += 1
                        project_files[project_id]['images'].append(original_filename)
                        print(f"✅ Added missing image: {original_filename} for project {project_id}")
    
    db.session.commit()
    
    # Also check for any orphaned files in the uploads directory
    upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'project_documents')
    if os.path.exists(upload_dir):
        for filename in os.listdir(upload_dir):
            # Check if this file exists in database
            existing = ProjectDocument.query.filter_by(file_path=filename).first()
            if not existing:
                # Try to determine file type from filename
                file_type = 'document'
                if filename.startswith('proof_'):
                    file_type = 'proof'
                elif filename.startswith('image_'):
                    file_type = 'image'
                
                # Try to extract project_id from filename
                try:
                    parts = filename.split('_')
                    if len(parts) >= 2:
                        if filename.startswith('proof_') or filename.startswith('image_'):
                            if len(parts) >= 3:
                                step_id = parts[1]
                                # Try to find step to get project_id
                                step = ProjectTracking.query.filter_by(id=step_id).first()
                                if step:
                                    project_id = step.project_id
                                else:
                                    project_id = 1
                            else:
                                project_id = 1
                        else:  # doc_ format
                            if len(parts) >= 2:
                                try:
                                    project_id = int(parts[1])
                                except:
                                    project_id = 1
                            else:
                                project_id = 1
                        
                        doc = ProjectDocument(
                            project_id=project_id,
                            file_name=filename,
                            file_path=filename,
                            file_type=file_type,
                            uploaded_at=datetime.utcnow()
                        )
                        db.session.add(doc)
                        fixed_count += 1
                        print(f"✅ Added orphaned file: {filename} for project {project_id} as type {file_type}")
                except Exception as e:
                    print(f"⚠️ Could not process orphaned file {filename}: {str(e)}")
    
    db.session.commit()
    
    # Get summary of fixed files by project
    summary = ""
    for project_id, files in project_files.items():
        project = Project.query.get(project_id)
        if project:
            total = len(files['proof']) + len(files['images'])
            if total > 0:
                summary += f"<br>📁 {project.title}: {total} files ({len(files['proof'])} proofs, {len(files['images'])} images)"
    
    if fixed_count > 0:
        flash(f'✅ Fixed {fixed_count} missing documents! They should now appear in the Summarize Documents section.{summary}', 'success')
    else:
        flash('No missing documents found. All files are already in the database.', 'info')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/messages')
@admin_required
def admin_messages():
    projects = Project.query.all()
    messages_dict = {}
    unread_counts = {}
    
    for project in projects:
        # Get all messages for this project
        project_messages = Message.query.filter_by(project_id=project.id).order_by(Message.timestamp).all()
        if project_messages:
            messages_dict[project] = project_messages
        
        # Count unread user messages
        unread_counts[project.id] = Message.query.filter_by(
            project_id=project.id, 
            sender='user', 
            is_read=False
        ).count()
    
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
    
    message = Message(project_id=project_id, sender='admin', message=message_text)
    db.session.add(message)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/admin/mark-messages-read/<int:project_id>', methods=['POST'])
@admin_required
def admin_mark_messages_read(project_id):
    # Mark all user messages as read
    Message.query.filter_by(project_id=project_id, sender='user', is_read=False).update({'is_read': True})
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/admin/get-unread-counts')
@admin_required
def admin_get_unread_counts():
    projects = Project.query.all()
    unread_counts = {}
    
    for project in projects:
        unread_counts[project.id] = Message.query.filter_by(
            project_id=project.id, 
            sender='user', 
            is_read=False
        ).count()
    
    return jsonify(unread_counts)

@app.route('/admin/contact-details')
@admin_required
def admin_contact_details():
    contact = ContactDetails.query.first()
    team_members = TeamMember.query.all()
    return render_template('admin.html', section='contact_details', contact=contact, team_members=team_members)

# Team Member Management Routes
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
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_filename = secure_filename(file.filename)
            filename = f"team_{timestamp}_{safe_filename}"
            
            # Save to team_photos directory
            team_photos_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'team_photos')
            full_path = os.path.join(team_photos_dir, filename)
            os.makedirs(team_photos_dir, exist_ok=True)
            file.save(full_path)
            photo_filename = filename
    
    # Create new team member
    team_member = TeamMember(
        name=name,
        role=role,
        email=email,
        mobile=mobile,
        photo=photo_filename
    )
    
    db.session.add(team_member)
    db.session.commit()
    
    flash(f'Team member {name} added successfully!', 'success')
    return redirect(url_for('admin_contact_details'))

@app.route('/admin/edit-team-member/<int:member_id>', methods=['POST'])
@admin_required
def edit_team_member(member_id):
    member = TeamMember.query.get_or_404(member_id)
    
    member.name = request.form.get('name', member.name)
    member.role = request.form.get('role', member.role)
    member.email = request.form.get('email', member.email)
    member.mobile = request.form.get('mobile', member.mobile)
    
    # Handle photo upload
    if 'photo' in request.files:
        file = request.files['photo']
        if file and file.filename and allowed_file(file.filename):
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_filename = secure_filename(file.filename)
            filename = f"team_{timestamp}_{safe_filename}"
            
            # Save to team_photos directory
            team_photos_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'team_photos')
            full_path = os.path.join(team_photos_dir, filename)
            os.makedirs(team_photos_dir, exist_ok=True)
            file.save(full_path)
            
            # Delete old photo if exists
            if member.photo:
                old_path = os.path.join(team_photos_dir, member.photo)
                if os.path.exists(old_path):
                    os.remove(old_path)
            
            member.photo = filename
    
    db.session.commit()
    flash(f'Team member {member.name} updated successfully!', 'success')
    return redirect(url_for('admin_contact_details'))

@app.route('/admin/delete-team-member/<int:member_id>', methods=['POST'])
@admin_required
def delete_team_member(member_id):
    member = TeamMember.query.get_or_404(member_id)
    
    # Delete photo if exists
    if member.photo:
        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], 'team_photos', member.photo)
        if os.path.exists(photo_path):
            os.remove(photo_path)
    
    db.session.delete(member)
    db.session.commit()
    flash(f'Team member {member.name} deleted successfully!', 'success')
    return redirect(url_for('admin_contact_details'))

@app.route('/admin/get-team-member/<int:member_id>')
@admin_required
def get_team_member(member_id):
    member = TeamMember.query.get_or_404(member_id)
    return jsonify({
        'id': member.id,
        'name': member.name,
        'role': member.role,
        'email': member.email,
        'mobile': member.mobile,
        'photo': member.photo
    })

@app.route('/admin/update-contact', methods=['POST'])
@admin_required
def update_contact():
    contact = ContactDetails.query.first()
    if not contact:
        contact = ContactDetails()
    
    contact.email = request.form.get('email')
    contact.phone = request.form.get('phone')
    contact.address = request.form.get('address')
    
    if not contact.id:
        db.session.add(contact)
    
    db.session.commit()
    flash('Contact details updated successfully!', 'success')
    return redirect(url_for('admin_contact_details'))

# Debug route to check documents
@app.route('/debug/documents')
@admin_required
def debug_documents():
    """Debug route to check documents"""
    docs_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'project_documents')
    files = []
    if os.path.exists(docs_dir):
        files = os.listdir(docs_dir)
    
    documents = ProjectDocument.query.all()
    doc_info = []
    for doc in documents:
        doc_info.append({
            'id': doc.id,
            'file_name': doc.file_name,
            'file_path': doc.file_path,
            'project_id': doc.project_id,
            'file_type': doc.file_type,
            'uploaded_at': str(doc.uploaded_at),
            'file_exists': os.path.exists(os.path.join(docs_dir, doc.file_path)) if doc.file_path else False,
            'url': url_for('project_document', filename=doc.file_path) if doc.file_path else None
        })
    
    result = {
        'documents_in_db': len(documents),
        'files_in_directory': len(files),
        'directory': docs_dir,
        'documents': doc_info,
        'files': files
    }
    
    return jsonify(result)

# Debug route to check profile photos
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Add new columns if they don't exist
        add_missing_columns()
        
        # Create default contact if not exists
        if not ContactDetails.query.first():
            default_contact = ContactDetails(
                email='admin@example.com',
                phone='+1234567890',
                address='123 Main Street, City, Country'
            )
            db.session.add(default_contact)
            db.session.commit()
        
        # Check for existing documents
        all_docs = ProjectDocument.query.all()
        print(f"📊 Total documents in database: {len(all_docs)}")
        for doc in all_docs:
            print(f"  - Document: {doc.file_name} -> {doc.file_path} (Type: {doc.file_type})")
        
        # Check for tracking steps with files not in ProjectDocument
        tracking_steps = ProjectTracking.query.all()
        missing_count = 0
        for step in tracking_steps:
            if step.proof_files:
                files = step.proof_files.split(',')
                for file_path in files:
                    if file_path and file_path.strip():
                        # Extract just the filename
                        filename = file_path.split('/')[-1] if '/' in file_path else file_path
                        existing = ProjectDocument.query.filter_by(file_path=filename).first()
                        if not existing:
                            print(f"⚠️ Missing document in ProjectDocument: {filename} (from {file_path})")
                            missing_count += 1
            if step.images:
                images = step.images.split(',')
                for image_path in images:
                    if image_path and image_path.strip():
                        # Extract just the filename
                        filename = image_path.split('/')[-1] if '/' in image_path else image_path
                        existing = ProjectDocument.query.filter_by(file_path=filename).first()
                        if not existing:
                            print(f"⚠️ Missing image in ProjectDocument: {filename} (from {image_path})")
                            missing_count += 1
        
        if missing_count > 0:
            print(f"\n⚠️ Found {missing_count} missing files. Visit /admin/fix-documents to fix them.")
        else:
            print("\n✅ All files are properly linked to ProjectDocument table.")
    
    app.run(debug=True)
