import os
from flask import Flask, render_template, request, send_file, redirect, url_for
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from dotenv import load_dotenv

# -------------------- CONFIGURATION --------------------
load_dotenv()  # Load keys from .env file

AES_KEY = os.getenv('AES_KEY')

# ✅ Check if key loaded correctly
if not AES_KEY or len(AES_KEY) not in [16, 24, 32]:
    print("⚠️ Invalid AES_KEY in .env — using default 16-byte key.")
    AES_KEY = "abcdefghijklmnop"  # Default 16-byte key
AES_KEY = AES_KEY.encode()

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# -------------------- ENCRYPT FUNCTION --------------------
def encrypt_file(input_path, output_path):
    cipher = AES.new(AES_KEY, AES.MODE_CBC)
    with open(input_path, 'rb') as f:
        data = f.read()
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    with open(output_path, 'wb') as f:
        f.write(cipher.iv + ct_bytes)


# -------------------- DECRYPT FUNCTION --------------------
def decrypt_file(input_path, output_path):
    with open(input_path, 'rb') as f:
        encrypted_data = f.read()
    iv = encrypted_data[:16]
    ct = encrypted_data[16:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ct), AES.block_size)
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)


# -------------------- ROUTES --------------------
@app.route('/')
def index():
    encrypted_files = [f for f in os.listdir(UPLOAD_FOLDER) if f.startswith('enc_')]
    return render_template('index.html', encrypted_files=encrypted_files)


# ---- Upload & Encrypt ----
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return render_template('index.html', message="⚠️ No file part")

    file = request.files['file']
    if file.filename == '':
        return render_template('index.html', message="⚠️ No file selected")

    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    # Encrypt and remove original file
    encrypted_path = os.path.join(UPLOAD_FOLDER, f'enc_{filename}')
    encrypt_file(filepath, encrypted_path)
    os.remove(filepath)

    encrypted_files = [f for f in os.listdir(UPLOAD_FOLDER) if f.startswith('enc_')]
    return render_template('index.html', filename=filename,
                           message=f"✅ File '{filename}' uploaded & encrypted successfully!",
                           encrypted_files=encrypted_files)


# ---- Decrypt & Download ----
@app.route('/decrypt', methods=['POST'])
def decrypt_and_download():
    filename = request.form.get('filename')
    encrypted_path = os.path.join(UPLOAD_FOLDER, filename)

    if not os.path.exists(encrypted_path):
        return render_template('index.html', message="⚠️ File not found!")

    decrypted_path = os.path.join(UPLOAD_FOLDER, f"decrypted_{filename[4:]}")  # remove 'enc_'
    decrypt_file(encrypted_path, decrypted_path)

    return send_file(decrypted_path, as_attachment=True)


# -------------------- MAIN --------------------
if __name__ == '__main__':
    app.run(debug=True)
