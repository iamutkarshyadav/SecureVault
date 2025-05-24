import os
import datetime
from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    files = db.relationship('EncryptedFile', backref='owner', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class EncryptedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    encrypted_filename = db.Column(db.String(255), nullable=False, unique=True)
    file_size = db.Column(db.Integer, nullable=False)  # Size in bytes
    content_type = db.Column(db.String(100))
    uploaded_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_accessed = db.Column(db.DateTime)
    encryption_algorithm = db.Column(db.String(50), default="AES-256-GCM")
    salt = db.Column(db.String(64), nullable=False)  # Salt used for key derivation
    iv = db.Column(db.String(64), nullable=False)    # Initialization vector
    tag = db.Column(db.String(64))                   # Authentication tag for AEAD ciphers
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shared_with = db.relationship('FileAccess', backref='file', lazy='dynamic')
    
    def get_file_path(self):
        """Get the path to the encrypted file on disk"""
        from app import app
        return os.path.join(app.config['UPLOAD_FOLDER'], self.encrypted_filename)
    
    def __repr__(self):
        return f'<EncryptedFile {self.original_filename}>'


class FileAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('encrypted_file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    granted_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    granted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    
    __table_args__ = (db.UniqueConstraint('file_id', 'user_id', name='_file_user_uc'),)
    
    user = db.relationship('User', foreign_keys=[user_id])
    granter = db.relationship('User', foreign_keys=[granted_by])
    
    def __repr__(self):
        return f'<FileAccess file_id={self.file_id} user_id={self.user_id}>'
