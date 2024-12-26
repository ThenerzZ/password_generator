import os
import shutil

def clean_sensitive_files():
    """Remove sensitive files before distribution"""
    files_to_remove = [
        'passwords.json',
        'master.hash',
        'master.salt',
        'encryption_key.key'
    ]
    
    directories_to_clean = [
        '__pycache__',
        'build',
        'dist',
        'secure_password_manager.egg-info'
    ]
    
    # Remove sensitive files
    for file in files_to_remove:
        if os.path.exists(file):
            os.remove(file)
            print(f"Removed: {file}")
    
    # Clean build directories
    for directory in directories_to_clean:
        if os.path.exists(directory):
            shutil.rmtree(directory)
            print(f"Removed directory: {directory}")

if __name__ == "__main__":
    clean_sensitive_files() 