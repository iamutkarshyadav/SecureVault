import os
import uuid
import logging
from datetime import datetime
from flask import render_template, flash, redirect, url_for, request, send_file, abort, g
from flask_login import login_user, logout_user, current_user, login_required
from urllib.parse import urlparse
from werkzeug.utils import secure_filename
import tempfile

from app import app, db
from forms import LoginForm, RegistrationForm, UploadFileForm, DecryptFileForm, ShareFileForm
from models import User, EncryptedFile, FileAccess
from crypto import CryptoManager

logger = logging.getLogger(__name__)

@app.context_processor
def inject_now():
    return {'now': datetime.now()}

@app.route('/')
@app.route('/index')
def index():
    """Home page route."""
    return render_template('index.html', title='Home')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('index')
        
        flash('You have successfully logged in!', 'success')
        return redirect(next_page)
    
    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    """User logout route."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Congratulations, you are now a registered user!', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', title='Register', form=form)

@app.route('/files')
@login_required
def files():
    """List all files owned by or shared with the current user."""
    # Get files owned by the user
    owned_files = EncryptedFile.query.filter_by(user_id=current_user.id).all()
    
    # Get files shared with the user
    shared_access = FileAccess.query.filter_by(user_id=current_user.id).all()
    shared_file_ids = [access.file_id for access in shared_access]
    shared_files = EncryptedFile.query.filter(EncryptedFile.id.in_(shared_file_ids)).all()
    
    return render_template('files.html', title='My Files', 
                           owned_files=owned_files, shared_files=shared_files)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    """Upload and encrypt a file."""
    form = UploadFileForm()
    if form.validate_on_submit():
        # Check if file was uploaded
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = form.file.data
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        
        try:
            # Save the file temporarily
            original_filename = secure_filename(file.filename)
            temp_dir = tempfile.mkdtemp()
            temp_path = os.path.join(temp_dir, original_filename)
            file.save(temp_path)
            
            # Generate a unique filename for the encrypted file
            encrypted_filename = f"{uuid.uuid4().hex}_{original_filename}.enc"
            encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
            
            # Encrypt the file
            encryption_password = form.encryption_password.data
            _, metadata = CryptoManager.encrypt_file(temp_path, encryption_password)
            
            # Move the encrypted file to the upload folder
            import shutil
            os.makedirs(os.path.dirname(encrypted_path), exist_ok=True)
            shutil.copy(f"{temp_path}.enc", encrypted_path)
            
            # Clean up temporary files
            os.remove(f"{temp_path}.enc")
            os.remove(temp_path)
            os.rmdir(temp_dir)
            
            # Save file metadata to database
            encrypted_file = EncryptedFile(
                original_filename=original_filename,
                encrypted_filename=encrypted_filename,
                file_size=os.path.getsize(encrypted_path),
                content_type=file.content_type if hasattr(file, 'content_type') else 'application/octet-stream',
                encryption_algorithm="AES-256-GCM",
                salt=metadata['salt'],
                iv=metadata['iv'],
                user_id=current_user.id
            )
            
            db.session.add(encrypted_file)
            db.session.commit()
            
            flash('File encrypted and uploaded successfully!', 'success')
            return redirect(url_for('files'))
            
        except Exception as e:
            logger.error(f"File encryption error: {str(e)}")
            flash(f'Error encrypting file: {str(e)}', 'danger')
    
    return render_template('upload.html', title='Upload File', form=form)

@app.route('/file/<int:file_id>')
@login_required
def file_details(file_id):
    """Show details of a specific file."""
    file = EncryptedFile.query.get_or_404(file_id)
    
    # Check if user has access to this file
    if file.user_id != current_user.id:
        # Check if file is shared with the user
        access = FileAccess.query.filter_by(file_id=file.id, user_id=current_user.id).first()
        if not access:
            flash('You do not have access to this file.', 'danger')
            return redirect(url_for('files'))
    
    # Get users this file is shared with
    shared_with = []
    if file.user_id == current_user.id:  # Only show sharing info to the owner
        accesses = FileAccess.query.filter_by(file_id=file.id).all()
        for access in accesses:
            user = User.query.get(access.user_id)
            if user:
                shared_with.append({
                    'username': user.username,
                    'granted_at': access.granted_at
                })
    
    return render_template('file_details.html', title=file.original_filename, 
                           file=file, shared_with=shared_with)

@app.route('/file/<int:file_id>/decrypt', methods=['GET', 'POST'])
@login_required
def decrypt_file(file_id):
    """Decrypt a file for downloading."""
    file = EncryptedFile.query.get_or_404(file_id)
    
    # Check if user has access to this file
    if file.user_id != current_user.id:
        # Check if file is shared with the user
        access = FileAccess.query.filter_by(file_id=file.id, user_id=current_user.id).first()
        if not access:
            flash('You do not have access to this file.', 'danger')
            return redirect(url_for('files'))
    
    form = DecryptFileForm()
    if form.validate_on_submit():
        try:
            # Get file paths
            encrypted_path = file.get_file_path()
            
            # Create a temporary directory for the decrypted file
            temp_dir = tempfile.mkdtemp()
            decrypted_path = os.path.join(temp_dir, file.original_filename)
            
            # Decrypt the file
            success = CryptoManager.decrypt_file(
                encrypted_path, decrypted_path, form.encryption_password.data,
                file.salt, file.iv
            )
            
            if not success:
                flash('Decryption failed. Check your password.', 'danger')
                return redirect(url_for('file_details', file_id=file.id))
            
            # Update last accessed time
            file.last_accessed = datetime.utcnow()
            db.session.commit()
            
            # Send the decrypted file to the user
            @app.after_request
            def remove_temp_file(response):
                try:
                    os.remove(decrypted_path)
                    os.rmdir(temp_dir)
                except Exception as e:
                    logger.error(f"Error removing temp file: {str(e)}")
                return response
            
            return send_file(
                decrypted_path,
                as_attachment=True,
                download_name=file.original_filename
            )
            
        except Exception as e:
            logger.error(f"File decryption error: {str(e)}")
            flash(f'Error decrypting file: {str(e)}', 'danger')
    
    return render_template('file_details.html', title=file.original_filename, 
                           file=file, form=form, decrypt_mode=True)

@app.route('/file/<int:file_id>/share', methods=['GET', 'POST'])
@login_required
def share_file(file_id):
    """Share a file with another user."""
    file = EncryptedFile.query.get_or_404(file_id)
    
    # Only the owner can share files
    if file.user_id != current_user.id:
        flash('You can only share files that you own.', 'danger')
        return redirect(url_for('files'))
    
    form = ShareFileForm()
    if form.validate_on_submit():
        # Find the user to share with
        target_user = User.query.filter_by(username=form.username.data).first()
        
        # Don't allow sharing with yourself
        if target_user.id == current_user.id:
            flash('You cannot share a file with yourself.', 'warning')
            return redirect(url_for('file_details', file_id=file.id))
        
        # Check if file is already shared with the user
        existing_access = FileAccess.query.filter_by(
            file_id=file.id, user_id=target_user.id
        ).first()
        
        if existing_access:
            flash(f'File is already shared with {target_user.username}.', 'warning')
            return redirect(url_for('file_details', file_id=file.id))
        
        try:
            # Create file access
            file_access = FileAccess(
                file_id=file.id,
                user_id=target_user.id,
                granted_by=current_user.id
            )
            
            db.session.add(file_access)
            db.session.commit()
            flash(f'File shared with {target_user.username}.', 'success')
            return redirect(url_for('file_details', file_id=file.id))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error sharing file: {str(e)}")
            flash(f'Error sharing file: {str(e)}', 'danger')
    
    return render_template('file_details.html', title=file.original_filename, 
                           file=file, share_form=form, share_mode=True)

@app.route('/file/<int:file_id>/delete', methods=['POST'])
@login_required
def delete_file(file_id):
    """Delete a file."""
    file = EncryptedFile.query.get_or_404(file_id)
    
    # Only the owner can delete files
    if file.user_id != current_user.id:
        flash('You can only delete files that you own.', 'danger')
        return redirect(url_for('files'))
    
    try:
        # Delete file access records
        FileAccess.query.filter_by(file_id=file.id).delete()
        
        # Delete the encrypted file from disk
        encrypted_path = file.get_file_path()
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
        
        # Delete the database record
        db.session.delete(file)
        db.session.commit()
        
        flash('File deleted successfully.', 'success')
        return redirect(url_for('files'))
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting file: {str(e)}")
        flash(f'Error deleting file: {str(e)}', 'danger')
        return redirect(url_for('file_details', file_id=file.id))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error_code=404, 
                           error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html', error_code=500, 
                           error_message="An unexpected error has occurred"), 500
