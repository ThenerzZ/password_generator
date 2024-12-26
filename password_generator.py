import tkinter as tk
from tkinter import ttk, messagebox
import string
import secrets
import json
from cryptography.fernet import Fernet
from pathlib import Path
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from theme import ModernTheme
import tkinter.font as tkfont
from base64 import b64encode, b64decode
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class PasswordGenerator:
    MAX_ATTEMPTS = 3  # Maximum number of password attempts
    
    def __init__(self):
        self.password_attempts = 0  # Initialize attempt counter
        self.stored_master_hash = None  # For storing the master password hash
        
        # Load stored master password hash if it exists
        self.load_master_hash()
        
        self.window = tk.Tk()
        self.window.title("Password Generator")
        self.window.geometry("900x800")
        self.window.configure(bg="#1E1E1E")
        
        # Apply modern theme
        self.style = ModernTheme.setup_theme()
        
        # Set window minimum size
        self.window.minsize(900, 700)
        
        # Add window corner radius (macOS style)
        try:
            self.window.tk.call("::tk::unsupported::MacWindowStyle", 
                              "style", self.window._w, "moveableModal", "dark")
        except:
            pass
        
        # Create main container with proper padding
        self.main_container = ttk.Frame(self.window, padding="40 30 40 30")
        
        # Create master password frame first
        self.master_password_frame = self.create_master_password_frame()
        self.master_password_frame.pack(fill="both", expand=True)
        
        # Initialize other attributes but don't show them yet
        self.saved_passwords = {}
        self.setup_encryption()
        self.create_widgets()  # Create but don't pack widgets yet
        
    def create_master_password_frame(self):
        """Create a styled master password frame"""
        frame = ttk.Frame(self.window, style="Card.TFrame", padding="40 30 40 30")
        
        # Create a container for centered content
        center_frame = ttk.Frame(frame, style="Card.TFrame")
        center_frame.pack(expand=True)
        
        # Title
        title_label = ttk.Label(
            center_frame,
            text="Password Manager",
            font=("SF Pro Display", 24, "bold"),
            foreground="#FFFFFF",
            background="#1E1E1E"
        )
        title_label.pack(pady=(0, 30))
        
        # Password entry container
        entry_frame = ttk.LabelFrame(
            center_frame,
            text="Enter Master Password",
            padding="20",
            style="Card.TLabelframe"
        )
        entry_frame.pack(fill="x", padx=20, pady=20)
        
        self.master_password_var = tk.StringVar()
        password_entry = ttk.Entry(
            entry_frame,
            textvariable=self.master_password_var,
            show="•",
            width=30,
            style="Rounded.TEntry"
        )
        password_entry.pack(pady=10, padx=20, fill="x")
        
        # Button container
        button_frame = ttk.Frame(entry_frame, style="Card.TFrame")
        button_frame.pack(pady=(20, 0))
        
        unlock_button = ttk.Button(
            button_frame,
            text="Unlock",
            command=self.unlock_with_master_password,
            style="Rounded.TButton"
        )
        unlock_button.pack()
        
        # Bind Enter key to unlock button
        password_entry.bind('<Return>', lambda e: unlock_button.invoke())
        password_entry.focus()
        
        return frame

    def unlock_with_master_password(self):
        """Handle master password submission"""
        master_password = self.master_password_var.get()
        if not master_password:
            messagebox.showerror("Error", "Master password is required")
            return
        
        try:
            # Setup master key
            salt_file = Path("master.salt")
            if salt_file.exists():
                with open(salt_file, "rb") as f:
                    self.salt = f.read()
            else:
                self.salt = os.urandom(16)
                with open(salt_file, "wb") as f:
                    f.write(self.salt)

            # Verify master password if it's not first time
            if self.stored_master_hash:
                if not self.verify_master_password(master_password):
                    self.password_attempts += 1
                    remaining_attempts = self.MAX_ATTEMPTS - self.password_attempts
                    
                    if remaining_attempts > 0:
                        messagebox.showerror(
                            "Error", 
                            f"Invalid master password. {remaining_attempts} attempts remaining."
                        )
                        self.master_password_var.set("")
                        return
                    else:
                        messagebox.showerror(
                            "Error", 
                            "Maximum password attempts exceeded. Application will close."
                        )
                        self.window.destroy()
                        return

            # Derive master key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=480000,
            )
            self.master_key = kdf.derive(master_password.encode())
            
            # If this is first time or password is correct, save the hash
            if not self.stored_master_hash:
                self.save_master_hash(master_password)
            
            # Try to load passwords to verify master password
            self.saved_passwords = self.load_passwords()
            
            # If we get here, master password was correct
            self.master_password_frame.destroy()  # Remove master password frame
            self.main_container.pack(fill="both", expand=True)  # Show main UI
            self.update_password_list()
            
        except Exception as e:
            messagebox.showerror("Error", "An error occurred while processing the master password")
            self.master_password_var.set("")

    def setup_encryption(self):
        # Generate or load encryption key
        key_file = Path("encryption_key.key")
        if key_file.exists():
            with open(key_file, "rb") as f:
                self.key = f.read()
        else:
            self.key = Fernet.generate_key()
            with open(key_file, "wb") as f:
                f.write(self.key)
        self.cipher_suite = Fernet(self.key)
        
    def encrypt_key(self, key):
        """Encrypt a password encryption key using the master key"""
        nonce = os.urandom(12)
        aes = AESGCM(self.master_key)
        encrypted_key = aes.encrypt(nonce, key, None)
        return b64encode(nonce + encrypted_key).decode()

    def decrypt_key(self, encrypted_key_str):
        """Decrypt a password encryption key using the master key"""
        encrypted_data = b64decode(encrypted_key_str)
        nonce = encrypted_data[:12]
        encrypted_key = encrypted_data[12:]
        aes = AESGCM(self.master_key)
        return aes.decrypt(nonce, encrypted_key, None)

    def create_widgets(self):
        # Password options frame
        options_frame = ttk.LabelFrame(
            self.main_container,
            text="Password Options",
            padding="20",
            style="Card.TLabelframe"
        )
        options_frame.pack(fill="x", padx=10, pady=(0, 20))
        
        # Grid configuration for better spacing
        options_frame.columnconfigure(1, weight=1)
        options_frame.columnconfigure(3, weight=1)
        
        # Length selection with modern styling
        ttk.Label(options_frame, text="Password Length:").grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.length_var = tk.IntVar(value=16)
        length_spin = ttk.Spinbox(
            options_frame,
            from_=8,
            to=64,
            textvariable=self.length_var,
            width=10,
            style="Rounded.TSpinbox"
        )
        length_spin.grid(row=0, column=1, sticky="w", pady=10)
        
        # Character type checkboxes
        checks_frame = ttk.Frame(options_frame, style="Card.TFrame")
        checks_frame.grid(row=1, column=0, columnspan=4, pady=10)
        
        self.use_uppercase = tk.BooleanVar(value=True)
        self.use_lowercase = tk.BooleanVar(value=True)
        self.use_numbers = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)
        
        for i, (text, var) in enumerate([
            ("Uppercase", self.use_uppercase),
            ("Lowercase", self.use_lowercase),
            ("Numbers", self.use_numbers),
            ("Symbols", self.use_symbols)
        ]):
            ttk.Checkbutton(
                checks_frame,
                text=text,
                variable=var,
                style="Rounded.TCheckbutton"
            ).pack(side="left", padx=10)
        
        # Generated password frame
        password_frame = ttk.LabelFrame(
            self.main_container,
            text="Generated Password",
            padding="20",
            style="Card.TLabelframe"
        )
        password_frame.pack(fill="x", padx=10, pady=(0, 20))
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(
            password_frame,
            textvariable=self.password_var,
            width=40,
            style="Output.TEntry",
            state="readonly"
        )
        self.password_entry.pack(side="left", padx=(0, 10), fill="x", expand=True)
        
        button_frame = ttk.Frame(password_frame, style="Card.TFrame")
        button_frame.pack(side="right")
        
        ttk.Button(
            button_frame,
            text="Generate",
            command=self.generate_password,
            style="Rounded.TButton"
        ).pack(side="left", padx=5)
        
        ttk.Button(
            button_frame,
            text="Copy",
            command=self.copy_password,
            style="Rounded.TButton"
        ).pack(side="left", padx=5)
        
        # Save password frame
        save_frame = ttk.LabelFrame(
            self.main_container,
            text="Save Password",
            padding="20",
            style="Card.TLabelframe"
        )
        save_frame.pack(fill="x", padx=10, pady=(0, 20))
        
        ttk.Label(save_frame, text="Password Name:").pack(side="left", padx=(0, 10))
        self.service_var = tk.StringVar()
        name_entry = ttk.Entry(
            save_frame,
            textvariable=self.service_var,
            width=30,
            style="Rounded.TEntry"
        )
        name_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ttk.Button(
            save_frame,
            text="Save Password",
            command=self.save_password,
            style="Rounded.TButton"
        ).pack(side="right")
        
        # Create a collapsible saved passwords section
        self.passwords_visible = tk.BooleanVar(value=True)
        passwords_header = ttk.Frame(self.main_container)
        passwords_header.pack(fill="x", padx=10, pady=(0, 5))
        
        ttk.Label(
            passwords_header,
            text="Saved Passwords",
            font=("SF Pro Display", 14, "bold")
        ).pack(side="left")
        
        self.toggle_btn = ttk.Button(
            passwords_header,
            text="▼",
            width=3,
            style="Rounded.TButton",
            command=self.toggle_passwords
        )
        self.toggle_btn.pack(side="right")

        # Saved passwords container
        self.passwords_container = ttk.Frame(self.main_container)
        self.passwords_container.pack(fill="both", expand=True, padx=10)
        
        # Create tree with modern styling
        self.passwords_tree = ttk.Treeview(
            self.passwords_container,
            columns=("Name", "Password"),
            show="headings",
            style="Rounded.Treeview"
        )
        self.passwords_tree.heading("Name", text="Name")
        self.passwords_tree.heading("Password", text="Password")
        self.passwords_tree.column("Name", width=200)
        self.passwords_tree.column("Password", width=200)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(
            self.passwords_container,
            orient="vertical",
            command=self.passwords_tree.yview,
            style="Rounded.Vertical.TScrollbar"
        )
        self.passwords_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack tree and scrollbar
        self.passwords_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Buttons for saved passwords
        button_frame = ttk.Frame(self.passwords_container)
        button_frame.pack(fill="x", pady=(20, 0))
        ttk.Button(
            button_frame,
            text="Delete Selected",
            command=self.delete_password,
            style="Rounded.TButton"
        ).pack(side="left", padx=5)
        ttk.Button(
            button_frame,
            text="Copy Selected",
            command=self.copy_selected_password,
            style="Rounded.TButton"
        ).pack(side="left", padx=5)
        
        # Add proper spacing between sections
        for child in self.main_container.winfo_children():
            if isinstance(child, ttk.LabelFrame):
                child.pack_configure(pady=15)
            else:
                child.pack_configure(pady=10)
        
        # Make the password entry more prominent
        self.password_entry.configure(font=("SF Mono", 16))
        
        # Add subtle hover effects for all buttons
        def add_hover_effect(button):
            button.bind("<Enter>", lambda e: e.widget.configure(cursor="hand2"))
            button.bind("<Leave>", lambda e: e.widget.configure(cursor=""))

        for widget in self.window.winfo_children():
            for button in widget.winfo_children():
                if isinstance(button, ttk.Button):
                    add_hover_effect(button)
        
    def generate_password(self):
        chars = ""
        if self.use_uppercase.get():
            chars += string.ascii_uppercase
        if self.use_lowercase.get():
            chars += string.ascii_lowercase
        if self.use_numbers.get():
            chars += string.digits
        if self.use_symbols.get():
            chars += string.punctuation
            
        if not chars:
            messagebox.showerror("Error", "Please select at least one character type")
            return
            
        password = ''.join(secrets.choice(chars) for _ in range(self.length_var.get()))
        self.password_var.set(password)
        
    def copy_password(self):
        self.window.clipboard_clear()
        self.window.clipboard_append(self.password_var.get())
        messagebox.showinfo("Success", "Password copied to clipboard!")
        
    def save_password(self):
        service = self.service_var.get().strip()
        password = self.password_var.get()
        
        if not service or not password:
            messagebox.showerror("Error", "Please enter both password name and generate a password")
            return
            
        # Generate and encrypt a new key for this password
        password_key = Fernet.generate_key()
        encrypted_key = self.encrypt_key(password_key)
        
        # Encrypt the password
        cipher_suite = Fernet(password_key)
        encrypted_password = cipher_suite.encrypt(password.encode()).decode()
        
        # Store encrypted password and encrypted key
        self.saved_passwords[service] = {
            'password': encrypted_password,
            'key': encrypted_key
        }
        
        self.save_passwords_to_file()
        self.update_password_list()
        self.service_var.set("")
        messagebox.showinfo("Success", "Password saved successfully!")
        
    def load_passwords(self):
        try:
            with open("passwords.json", "r") as f:
                data = json.load(f)
                # Validate the data structure
                if not isinstance(data, dict):
                    return {}
                return data
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError:
            print("Error: Corrupted passwords file")
            return {}
            
    def save_passwords_to_file(self):
        with open("passwords.json", "w") as f:
            json.dump(self.saved_passwords, f)
            
    def update_password_list(self):
        for item in self.passwords_tree.get_children():
            self.passwords_tree.delete(item)
        for name, data in self.saved_passwords.items():
            try:
                if isinstance(data, dict) and 'password' in data and 'key' in data:
                    # Decrypt the password key first
                    key = self.decrypt_key(data['key'])
                    cipher_suite = Fernet(key)
                    decrypted_password = cipher_suite.decrypt(data['password'].encode()).decode()
                else:
                    decrypted_password = "Error: Invalid format"
                
                self.passwords_tree.insert("", "end", values=(name, "*" * len(decrypted_password)))
            except Exception as e:
                print(f"Error decrypting password for {name}: {str(e)}")
                self.passwords_tree.insert("", "end", values=(name, "Error: Decryption failed"))
            
    def delete_password(self):
        selected = self.passwords_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a password to delete")
            return
            
        service = self.passwords_tree.item(selected[0])["values"][0]
        if messagebox.askyesno("Confirm", f"Delete password for {service}?"):
            del self.saved_passwords[service]
            self.save_passwords_to_file()
            self.update_password_list()
            
    def copy_selected_password(self):
        selected = self.passwords_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a password to copy")
            return
            
        service = self.passwords_tree.item(selected[0])["values"][0]
        data = self.saved_passwords[service]
        
        # Create cipher suite with the password's specific key
        key = b64decode(data['key'])
        cipher_suite = Fernet(key)
        decrypted_password = cipher_suite.decrypt(data['password'].encode()).decode()
        
        self.window.clipboard_clear()
        self.window.clipboard_append(decrypted_password)
        messagebox.showinfo("Success", "Password copied to clipboard!")
        
    def toggle_passwords(self):
        if self.passwords_visible.get():
            self.passwords_container.pack_forget()
            self.toggle_btn.configure(text="▶")
        else:
            self.passwords_container.pack(fill="both", expand=True, padx=10)
            self.toggle_btn.configure(text="▼")
        self.passwords_visible.set(not self.passwords_visible.get())
        
    def run(self):
        self.update_password_list()
        self.window.mainloop()

    def load_master_hash(self):
        """Load stored master password hash"""
        try:
            with open("master.hash", "rb") as f:
                self.stored_master_hash = f.read()
        except FileNotFoundError:
            self.stored_master_hash = None

    def save_master_hash(self, password):
        """Save master password hash"""
        # Create a hash of the master password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=480000,
        )
        password_hash = kdf.derive(password.encode())
        
        # Save the hash
        with open("master.hash", "wb") as f:
            f.write(password_hash)
        self.stored_master_hash = password_hash

    def verify_master_password(self, password):
        """Verify if master password is correct"""
        if not self.stored_master_hash:
            return True  # First time setup
            
        # Create hash of entered password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=480000,
        )
        try:
            kdf.verify(password.encode(), self.stored_master_hash)
            return True
        except:
            return False

if __name__ == "__main__":
    app = PasswordGenerator()
    app.run() 