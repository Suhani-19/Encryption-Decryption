from flask import Flask, request, render_template, send_from_directory, redirect
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Protocol.KDF import scrypt
import os
import mysql.connector
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


app = Flask(__name__)

# Set up directories for file uploads and encrypted/decrypted files
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
ENCRYPTED_FOLDER = os.path.join(os.getcwd(), 'encrypted')
DECRYPTED_FOLDER = os.path.join(os.getcwd(), 'decrypted')

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

# Helper function to derive key from password using scrypt
def derive_key(password: str, salt: bytes):
    return scrypt(password.encode(), salt, 32, N=2**14, r=8, p=1)

# AES encryption
def encrypt_file(file_path: str, password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC)
    
    with open(file_path, 'rb') as f:
        file_data = f.read()

    encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))

    # Save the encrypted file with salt and IV included
    encrypted_filename = f"encrypted_{os.path.basename(file_path)}"
    encrypted_file_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)
    
    with open(encrypted_file_path, 'wb') as f:
        f.write(salt + cipher.iv + encrypted_data)

    return encrypted_file_path

# AES decryption
def decrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    salt = file_data[:16]
    iv = file_data[16:32]
    encrypted_data = file_data[32:]

    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    try:
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    except (ValueError, KeyError):
        return None  # Return None if decryption fails

    # Save the decrypted file
    decrypted_filename = f"decrypted_{os.path.basename(file_path)}"
    decrypted_file_path = os.path.join(DECRYPTED_FOLDER, decrypted_filename)

    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)

    return decrypted_file_path

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login')  # Route for Login Page
def login():
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)

@app.route('/upload', methods=['POST'])
def upload_file():
    password = request.form.get('password')
    if 'file' not in request.files or not password:
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    
    if file:
        filename = file.filename
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)
        
        encrypted_file_path = encrypt_file(file_path, password)
        
        return f'File encrypted and saved as <a href="/download/{os.path.basename(encrypted_file_path)}">{os.path.basename(encrypted_file_path)}</a>'

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    file_path = os.path.join(ENCRYPTED_FOLDER, filename)
    if os.path.exists(file_path):
        response = send_from_directory(ENCRYPTED_FOLDER, filename)
        response.headers['Content-Disposition'] = f'attachment; filename={filename}'
        response.cache_control.no_cache = True
        response.cache_control.no_store = True
        response.cache_control.must_revalidate = True
        return response
    return 'File not found', 404

@app.route('/decrypt', methods=['POST'])
def decrypt_file_route():
    password = request.form.get('password')
    if 'file' not in request.files or not password:
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    
    if file:
        filename = file.filename
        file_path = os.path.join(ENCRYPTED_FOLDER, filename)
        file.save(file_path)
        
        decrypted_file_path = decrypt_file(file_path, password)
        
        if decrypted_file_path is None:
            return 'Invalid password or file data', 400
        
        return f'File decrypted and saved as <a href="/decrypted/{os.path.basename(decrypted_file_path)}">{os.path.basename(decrypted_file_path)}</a>'

@app.route('/decrypted/<filename>', methods=['GET'])
def download_decrypted_file(filename):
    file_path = os.path.join(DECRYPTED_FOLDER, filename)
    if os.path.exists(file_path):
        return send_from_directory(DECRYPTED_FOLDER, filename)
    return 'File not found', 404

if __name__ == '__main__':
    app.run(debug=True)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        file = request.files['file']
        password = request.form['password']
        user_id = request.form['user_id']  # Assuming you pass this from the frontend

        file_data = file.read()
        encrypted_data = encrypt_data(file_data, password)

        # Store encrypted file in database
        cursor.execute(
            "INSERT INTO file_passwords (password, user_id, filename, encrypted_data) VALUES (%s, %s, %s, %s)",
            (password, user_id, file.filename, encrypted_data)
        )
        db.commit()

        return jsonify({"message": "File encrypted and saved successfully!"}), 200

    except Exception as e:
        return jsonify({"error": f"Error during encryption: {str(e)}"}), 500



@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        password = request.form['password']
        filename = request.form['filename']

        # Retrieve encrypted file from database
        cursor.execute(
            "SELECT encrypted_data FROM file_passwords WHERE filename = %s AND password = %s",
            (filename, password)
        )
        result = cursor.fetchone()

        if not result:
            return jsonify({"error": "File not found or incorrect password"}), 404

        encrypted_data = result[0]
        decrypted_data = decrypt_data(encrypted_data, password)

        return send_file(
            io.BytesIO(decrypted_data),
            as_attachment=True,
            download_name="decrypted_" + filename,
            mimetype="application/octet-stream"
        )

    except Exception as e:
        return jsonify({"error": f"Error during decryption: {str(e)}"}), 500


db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="your_password",
    database="encryption_db"
)

cursor = db.cursor()

#add user login route
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    cursor.execute("SELECT user_id, username FROM users WHERE user_id = %s", (user_id,))
    user = cursor.fetchone()
    if user:
        return User(user[0], user[1])
    return None

@app.route('/login', methods=['POST'])
def login():
    user_email = request.form['email']
    password = request.form['password']

    cursor.execute("SELECT user_id, username, password_hash FROM users WHERE user_email = %s", (user_email,))
    user = cursor.fetchone()

    if user and check_password_hash(user[2], password):
        user_obj = User(user[0], user[1])
        login_user(user_obj)
        return jsonify({"message": "Login successful"}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401
