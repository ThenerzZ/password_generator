# Secure Password Manager

A modern, secure password manager with an Apple-inspired dark mode UI built in Python. This application provides a secure way to generate, store, and manage passwords with multiple layers of encryption and security features.


## Features

### Security
- Master password protection with attempt limiting (3 attempts)
- Individual encryption keys for each stored password
- PBKDF2 key derivation for master password (480,000 iterations)
- AES-GCM authenticated encryption for password keys
- Fernet symmetric encryption for passwords
- Secure random number generation for passwords
- No plaintext storage of any passwords
- Automatic clipboard clearing after copying

### Password Generation
- Customizable password length (8-64 characters)
- Configurable character sets:
  - Uppercase letters (A-Z)
  - Lowercase letters (a-z)
  - Numbers (0-9)
  - Special characters (!@#$%^&*)
- Cryptographically secure random generation

### User Interface
- Modern macOS-inspired dark mode interface
- Clean and intuitive design
- Collapsible saved passwords section
- Password strength indicators
- Copy to clipboard functionality
- Responsive layout
- Smooth animations and transitions

### Password Management
- Secure storage of multiple passwords
- Password organization by name/service
- Quick copy functionality
- Secure deletion
- Password preview (masked)
- Search and filter capabilities

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/ThenerzZ/password_generator
cd password-manager
```
2. Create a virtual environment and install the dependencies:
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
3. Activate the virtual environment:
```bash
source venv/bin/activate
```
4. Run the application:
```bash
python main.py
```
4. Install required packages:
```bash
pip install -r requirements.txt
```
## Usage

1. Run the application:
```bash
python password_generator.py
```
2. First time setup: 
- Enter a master password
- This password will be required to access the application
- If you forget your master password, you will not be able to access your passwords
- make shure to remember your master password

3. Generate a password:
- Enter the desired password length and character types
- Click "Generate" to create a new password
- The generated password will be displayed in the output field
- Click "Save" to store the password in the application

4. View and manage stored passwords:
- Click "View Passwords" to see a list of all stored passwords
- Click "Copy" to copy a password to your clipboard
- Click "Delete" to remove a password from the application

## Security Architecture

### Encryption Layers
1. Master Password protection:
- PBKDF2 key derivation for master password (480,000 iterations)
- Unique salt for each master instllation
- stored as secure hash in passwords.json

2. Individal Password Protection:
- Unique Fernet key for each password
- Keys encrypted with AES-GCM
- Master Key required to decrypt keys

3. Storage Security:
- No plaintext storage of any passwords
- Encrypted JSON storage
- Protected key storage

## File Structure
- `password_generator.py`: Main application for generating and managing passwords
- `theme.py`: Custom theme for the application
- `passwords.json`: JSON file for storing passwords
- `master.hash`: Master password hash
- `master.salt`: Salt for master password
- `encryption_key.key`: Base encryption key
- `requirements.txt`: List of dependencies
- `README.md`: This file

## Dependencies
- cryptography>=3.4.7: For encryption and decryption
- pillow>=8.0.000000000: For improved font rendering
- tkinter: For GUI (included with Python)

## Security Considerations
- Master password is never stored in plaintext
- Each password is encrypted with a unique key
- Failed master password attempts are limited
- Clipboard is cleared after copying
- No logging of any user activity
- Secure random number generation for passwords
- Memory is cleared after use

## Development
- Written in Python 3
- Uses tkinter for GUI
- Modern class based design
- Extensive error handling 
- Follows best practices for secure password management

## License

This project is open-sourced under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Thanks to the Python community for the libraries and tools used in this project
- Inspired by the macOS interface and design

## Support
For support, please open an issue on the GitHub repository.

## Disclaimer
While this application is designed to be secure, no security system can guarantee 100% protection against all attacks. Always use strong, unique passwords for your accounts and consider additional security measures such as two-factor authentication.

