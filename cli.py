#!/usr/bin/env python
import os
import sys
import argparse
import getpass
import logging
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Configure logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def setup_db_session():
    """Set up and return a database session."""
    db_url = os.environ.get("DATABASE_URL", "sqlite:///encryption.db")
    engine = create_engine(db_url)
    Session = sessionmaker(bind=engine)
    return Session()

def register_user(args):
    """Register a new user in the system."""
    from models import User
    
    session = setup_db_session()
    
    # Check if user already exists
    existing_user = session.query(User).filter(
        (User.username == args.username) | (User.email == args.email)
    ).first()
    
    if existing_user:
        logger.error("User with that username or email already exists.")
        return
    
    # Create new user
    user = User(username=args.username, email=args.email)
    
    # Get and set password
    password = getpass.getpass("Enter password: ")
    confirm_password = getpass.getpass("Confirm password: ")
    
    if password != confirm_password:
        logger.error("Passwords do not match.")
        return
    
    user.set_password(password)
    
    try:
        session.add(user)
        session.commit()
        logger.info(f"User {args.username} registered successfully.")
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to register user: {str(e)}")
    finally:
        session.close()

def encrypt_file(args):
    """Encrypt a file and store metadata in the database."""
    from models import User, EncryptedFile
    from crypto import CryptoManager
    import uuid
    
    session = setup_db_session()
    
    # Authenticate user
    user = session.query(User).filter_by(username=args.username).first()
    if not user:
        logger.error("User not found.")
        return
    
    password = getpass.getpass("Enter your password: ")
    if not user.check_password(password):
        logger.error("Authentication failed: incorrect password.")
        return
    
    # Check if file exists
    if not os.path.exists(args.file):
        logger.error(f"File {args.file} not found.")
        return
    
    file_size = os.path.getsize(args.file)
    original_filename = os.path.basename(args.file)
    
    # Get encryption password
    enc_password = getpass.getpass("Enter encryption password: ")
    confirm_password = getpass.getpass("Confirm encryption password: ")
    
    if enc_password != confirm_password:
        logger.error("Encryption passwords do not match.")
        return
    
    # Generate a unique filename for the encrypted file
    encrypted_filename = f"{uuid.uuid4().hex}_{original_filename}.enc"
    encrypted_path = os.path.join(
        os.environ.get("UPLOAD_FOLDER", "encrypted_files"), 
        encrypted_filename
    )
    
    try:
        # Make sure the upload folder exists
        os.makedirs(os.path.dirname(encrypted_path), exist_ok=True)
        
        # Encrypt the file
        _, metadata = CryptoManager.encrypt_file(args.file, enc_password)
        
        # Move the encrypted file to the upload folder
        import shutil
        shutil.copy(f"{args.file}.enc", encrypted_path)
        os.remove(f"{args.file}.enc")  # Remove the temporary encrypted file
        
        # Store metadata in database
        encrypted_file = EncryptedFile(
            original_filename=original_filename,
            encrypted_filename=encrypted_filename,
            file_size=file_size,
            content_type="application/octet-stream",
            encryption_algorithm="AES-256-GCM",
            salt=metadata['salt'],
            iv=metadata['iv'],
            user_id=user.id
        )
        
        session.add(encrypted_file)
        session.commit()
        logger.info(f"File encrypted successfully: {encrypted_path}")
        
    except Exception as e:
        session.rollback()
        logger.error(f"Encryption failed: {str(e)}")
    finally:
        session.close()

def decrypt_file(args):
    """Decrypt a file from the database."""
    from models import User, EncryptedFile
    from crypto import CryptoManager
    
    session = setup_db_session()
    
    # Authenticate user
    user = session.query(User).filter_by(username=args.username).first()
    if not user:
        logger.error("User not found.")
        return
    
    password = getpass.getpass("Enter your password: ")
    if not user.check_password(password):
        logger.error("Authentication failed: incorrect password.")
        return
    
    # Find the file
    encrypted_file = session.query(EncryptedFile).filter_by(id=args.file_id).first()
    if not encrypted_file:
        logger.error(f"File with ID {args.file_id} not found.")
        return
    
    # Check if user has access to the file
    if encrypted_file.user_id != user.id:
        # Check if the file is shared with the user
        from models import FileAccess
        file_access = session.query(FileAccess).filter_by(
            file_id=encrypted_file.id, user_id=user.id
        ).first()
        
        if not file_access:
            logger.error("You don't have access to this file.")
            return
    
    # Get encryption password
    enc_password = getpass.getpass("Enter encryption password: ")
    
    # Set up the output path
    output_path = args.output or f"decrypted_{encrypted_file.original_filename}"
    
    try:
        # Path to the encrypted file
        encrypted_path = encrypted_file.get_file_path()
        
        if not os.path.exists(encrypted_path):
            logger.error(f"Encrypted file not found at {encrypted_path}")
            return
        
        # Decrypt the file
        success = CryptoManager.decrypt_file(
            encrypted_path, output_path, enc_password,
            encrypted_file.salt, encrypted_file.iv
        )
        
        if success:
            # Update last accessed time
            encrypted_file.last_accessed = datetime.utcnow()
            session.commit()
            logger.info(f"File decrypted successfully: {output_path}")
        else:
            logger.error("Decryption failed. Check your encryption password.")
            
    except Exception as e:
        session.rollback()
        logger.error(f"Decryption failed: {str(e)}")
    finally:
        session.close()

def list_files(args):
    """List all encrypted files owned by the user."""
    from models import User, EncryptedFile
    
    session = setup_db_session()
    
    # Authenticate user
    user = session.query(User).filter_by(username=args.username).first()
    if not user:
        logger.error("User not found.")
        return
    
    password = getpass.getpass("Enter your password: ")
    if not user.check_password(password):
        logger.error("Authentication failed: incorrect password.")
        return
    
    # Get all files owned by the user
    files = session.query(EncryptedFile).filter_by(user_id=user.id).all()
    
    if not files:
        logger.info("You don't have any encrypted files.")
        return
    
    # Print file information
    print("\n{:<5} {:<30} {:<15} {:<20}".format("ID", "Filename", "Size (KB)", "Uploaded At"))
    print("-" * 70)
    
    for file in files:
        size_kb = file.file_size / 1024
        print("{:<5} {:<30} {:<15.2f} {:<20}".format(
            file.id, file.original_filename, size_kb, 
            file.uploaded_at.strftime("%Y-%m-%d %H:%M")
        ))
    
    session.close()

def share_file(args):
    """Share an encrypted file with another user."""
    from models import User, EncryptedFile, FileAccess
    
    session = setup_db_session()
    
    # Authenticate user
    user = session.query(User).filter_by(username=args.username).first()
    if not user:
        logger.error("User not found.")
        return
    
    password = getpass.getpass("Enter your password: ")
    if not user.check_password(password):
        logger.error("Authentication failed: incorrect password.")
        return
    
    # Find the file
    encrypted_file = session.query(EncryptedFile).filter_by(id=args.file_id).first()
    if not encrypted_file:
        logger.error(f"File with ID {args.file_id} not found.")
        return
    
    # Check if user owns the file
    if encrypted_file.user_id != user.id:
        logger.error("You can only share files that you own.")
        return
    
    # Find the user to share with
    target_user = session.query(User).filter_by(username=args.target_username).first()
    if not target_user:
        logger.error(f"User {args.target_username} not found.")
        return
    
    # Check if file is already shared with the user
    existing_access = session.query(FileAccess).filter_by(
        file_id=encrypted_file.id, user_id=target_user.id
    ).first()
    
    if existing_access:
        logger.error(f"File is already shared with {args.target_username}.")
        return
    
    try:
        # Create file access
        file_access = FileAccess(
            file_id=encrypted_file.id,
            user_id=target_user.id,
            granted_by=user.id
        )
        
        session.add(file_access)
        session.commit()
        logger.info(f"File {encrypted_file.original_filename} shared with {args.target_username}.")
        
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to share file: {str(e)}")
    finally:
        session.close()

def main():
    """Main function for the CLI."""
    parser = argparse.ArgumentParser(description="File Encryption System CLI")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Register user parser
    register_parser = subparsers.add_parser("register", help="Register a new user")
    register_parser.add_argument("username", help="Username")
    register_parser.add_argument("email", help="Email address")
    
    # Encrypt file parser
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt_parser.add_argument("username", help="Username")
    encrypt_parser.add_argument("file", help="Path to file to encrypt")
    
    # Decrypt file parser
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    decrypt_parser.add_argument("username", help="Username")
    decrypt_parser.add_argument("file_id", type=int, help="ID of the file to decrypt")
    decrypt_parser.add_argument("--output", "-o", help="Output file path")
    
    # List files parser
    list_parser = subparsers.add_parser("list", help="List encrypted files")
    list_parser.add_argument("username", help="Username")
    
    # Share file parser
    share_parser = subparsers.add_parser("share", help="Share a file with another user")
    share_parser.add_argument("username", help="Your username")
    share_parser.add_argument("file_id", type=int, help="ID of the file to share")
    share_parser.add_argument("target_username", help="Username to share with")
    
    args = parser.parse_args()
    
    if args.command == "register":
        register_user(args)
    elif args.command == "encrypt":
        encrypt_file(args)
    elif args.command == "decrypt":
        decrypt_file(args)
    elif args.command == "list":
        list_files(args)
    elif args.command == "share":
        share_file(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
