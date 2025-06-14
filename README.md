
from pathlib import Path
import zipfile

project_root = Path("/mnt/data/encryption_app")
project_root.mkdir(parents=True, exist_ok=True)

# File contents
files = {
    "main.py": """
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from custom_crypto import custom_encrypt, custom_decrypt
from rsa_signature import generate_keys, sign_data, verify_signature
from auth import login_user, register_user, initialize_db

# Initialize DB and RSA keys
initialize_db()
generate_keys()

class EncryptionApp:
    def _init_(self, root):
        self.root = root
        self.root.title("Secure Encryption App")
        self.username = None
        self.build_login()

    def build_login(self):
        self.clear_window()
        tk.Label(self.root, text="Login", font=("Arial", 16)).pack(pady=10)

        tk.Label(self.root, text="Username").pack()
        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack()

        tk.Label(self.root, text="Password").pack()
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack()

        tk.Button(self.root, text="Login", command=self.login).pack(pady=5)
        tk.Button(self.root, text="Register", command=self.register).pack()

    def build_main(self):
        self.clear_window()
        tk.Label(self.root, text=f"Welcome, {self.username}", font=("Arial", 14)).pack(pady=5)

        self.text_box = scrolledtext.ScrolledText(self.root, width=50, height=10)
        self.text_box.pack()

        self.result_box = scrolledtext.ScrolledText(self.root, width=50, height=10)
        self.result_box.pack()

        tk.Button(self.root, text="Encrypt Text", command=self.encrypt_text).pack(pady=5)
        tk.Button(self.root, text="Decrypt Text", command=self.decrypt_text).pack()

        tk.Button(self.root, text="Upload File", command=self.upload_file).pack(pady=5)

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if login_user(username, password):
            self.username = username
            self.build_main()
        else:
            messagebox.showerror("Login Failed", "Invalid credentials")

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if register_user(username, password):
            messagebox.showinfo("Registration", "User registered successfully!")
        else:
            messagebox.showerror("Registration Failed", "User already exists.")

    def encrypt_text(self):
        text = self.text_box.get("1.0", tk.END).strip()
        key = 0x5A
        encrypted = custom_encrypt(text, key)
        signature = sign_data(encrypted)
        self.result_box.delete("1.0", tk.END)
        self.result_box.insert(tk.END, encrypted.hex() + "\\nSignature: " + signature.hex())

    def decrypt_text(self):
        lines = self.result_box.get("1.0", tk.END).strip().split("\\n")
        if len(lines) < 2:
            messagebox.showerror("Error", "Invalid format")
            return
        ciphertext = bytes.fromhex(lines[0])
        signature = bytes.fromhex(lines[1].split(": ")[1])
        if verify_signature(ciphertext, signature):
            key = 0x5A
            decrypted = custom_decrypt(ciphertext, key)
            self.text_box.delete("1.0", tk.END)
            self.text_box.insert(tk.END, decrypted)
        else:
            messagebox.showerror("Error", "Invalid signature!")

    def upload_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            with open(filepath, "rb") as f:
                data = f.read()
            encrypted = custom_encrypt(data.decode('utf-8', errors='ignore'), 0x5A)
            with open(filepath + ".enc", "wb") as f:
                f.write(encrypted)
            messagebox.showinfo("File Encrypted", f"Encrypted file saved as {filepath}.enc")

root = tk.Tk()
app = EncryptionApp(root)
root.mainloop()
""",

    "custom_crypto.py": """
def custom_round(data, key):
    return ((data & key) | ((data << 1) & 0xFF)) ^ (key >> 1)

def custom_encrypt(text, key):
    encrypted = bytearray()
    for i, ch in enumerate(text.encode()):
        round_key = (key + i) % 256
        encrypted.append(custom_round(ch, round_key))
    return encrypted

def custom_decrypt(data, key):
    decrypted = ""
    for i, byte in enumerate(data):
        round_key = (key + i) % 256
        # reverse logic: guess-and-check (simple brute-force for demo purposes)
        for guess in range(256):
            if custom_round(guess, round_key) == byte:
                decrypted += chr(guess)
                break
    return decrypted
""",

    "rsa_signature.py": """
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

key_file = "private.pem"
pub_file = "public.pem"

def generate_keys():
    try:
        RSA.import_key(open(key_file).read())
    except:
        key = RSA.generate(2048)
        with open(key_file, "wb") as f:
            f.write(key.export_key())
        with open(pub_file, "wb") as f:
            f.write(key.publickey().export_key())

def sign_data(data):
    key = RSA.import_key(open(key_file).read())
    h = SHA256.new(data)
    return pkcs1_15.new(key).sign(h)

def verify_signature(data, signature):
    key = RSA.import_key(open(pub_file).read())
    h = SHA256.new(data)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except:
        return False
""",

    "auth.py": """
import sqlite3
import bcrypt

def initialize_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)")
    conn.commit()
    conn.close()

def register_user(username, password):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    try:
        c.execute("INSERT INTO users VALUES (?, ?)", (username, hashed))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def login_user(username, password):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    if row and bcrypt.checkpw(password.encode(), row[0]):
        return True
    return False
"""
}

# Write files
for filename, content in files.items():
    file_path = project_root / filename
    with open(file_path, "w") as f:
        f.write(content.strip())

# Create ZIP
zip_path = "/mnt/data/encryption_app.zip"
with zipfile.ZipFile(zip_path, "w") as zipf:
    for file in project_root.rglob("*"):
        zipf.write(file, arcname=file.relative_to(project_root))

zip_path.name  # Return just the filename to the user
