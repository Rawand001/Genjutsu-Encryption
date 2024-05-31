import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QTextEdit, QPushButton, QLineEdit, QHBoxLayout, QLabel, QGridLayout
from PyQt5.QtCore import Qt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import sqlite3
import hashlib

user1_key = RSA.generate(2048)
user2_key = RSA.generate(2048)

user1_public_key = user1_key.publickey()
user2_public_key = user2_key.publickey()

conn = sqlite3.connect('conversations.db')
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actual_msg TEXT,
                    generated_msg TEXT)''')
conn.commit()

def hash_message(message):
    return hashlib.sha256(message.encode('utf-8')).hexdigest()

def encrypt_message_rsa(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode('utf-8'))
    return base64.b64encode(encrypted_message).decode('utf-8')

def decrypt_message_rsa(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(base64.b64decode(ciphertext))
    return decrypted_message.decode('utf-8')

current_topic_id = None
current_dialogue_index = 0

def reset_conversation_state():
    global current_topic_id, current_dialogue_index
    current_topic_id = None
    current_dialogue_index = 0

def get_next_message():
    global current_topic_id, current_dialogue_index
    if current_topic_id is None or current_dialogue_index >= 30:
        cursor.execute('SELECT id FROM topics ORDER BY RANDOM() LIMIT 1')
        current_topic_id = cursor.fetchone()[0]
        current_dialogue_index = 0
    cursor.execute('SELECT message FROM dialogues WHERE topic_id = ? ORDER BY id LIMIT 1 OFFSET ?', (current_topic_id, current_dialogue_index))
    message = cursor.fetchone()
    if message:
        current_dialogue_index += 1
        return message[0].split(": ", 1)[1]  
    else:
        return None

class EncryptionApp(QWidget):
    def __init__(self):
        super().__init__()
        reset_conversation_state()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('RSA Encryption Simulation')
        self.setGeometry(100, 100, 900, 600)

        self.setStyleSheet("""
            QWidget {
                background-color: #f0f0f0;
            }
            QTextEdit {
                background-color: #ffffff;
                color: #000000;
                font: 12pt "Helvetica";
                border: 1px solid #cccccc;
                border-radius: 10px;
                padding: 10px;
            }
            QLineEdit {
                background-color: #ffffff;
                color: #000000;
                font: 12pt "Helvetica";
                border: 1px solid #cccccc;
                border-radius: 10px;
                padding: 10px;
                height: 40px;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font: 12pt "Helvetica";
                border: none;
                border-radius: 10px;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QLabel {
                font: 14pt "Helvetica";
                margin-bottom: 10px;
            }
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)

        grid_layout = QGridLayout()
        grid_layout.setSpacing(20)

        user1_label = QLabel("User 1", self)
        grid_layout.addWidget(user1_label, 0, 0, Qt.AlignCenter)

        mitm_label = QLabel("MITM", self)
        grid_layout.addWidget(mitm_label, 0, 1, Qt.AlignCenter)

        user2_label = QLabel("User 2", self)
        grid_layout.addWidget(user2_label, 0, 2, Qt.AlignCenter)

        self.user1_display = QTextEdit(self)
        self.user1_display.setReadOnly(True)
        grid_layout.addWidget(self.user1_display, 1, 0)

        self.mitm_display = QTextEdit(self)
        self.mitm_display.setReadOnly(True)
        grid_layout.addWidget(self.mitm_display, 1, 1)

        self.user2_display = QTextEdit(self)
        self.user2_display.setReadOnly(True)
        grid_layout.addWidget(self.user2_display, 1, 2)

        layout.addLayout(grid_layout)

        self.input_text = QLineEdit(self)
        layout.addWidget(self.input_text)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(20)
        
        self.send_button_user1 = QPushButton('Send as User 1', self)
        self.send_button_user1.clicked.connect(lambda: self.send_message("User 1", user2_public_key, user2_key))
        button_layout.addWidget(self.send_button_user1)
        
        self.send_button_user2 = QPushButton('Send as User 2', self)
        self.send_button_user2.setStyleSheet("background-color: #2196F3;")
        self.send_button_user2.clicked.connect(lambda: self.send_message("User 2", user1_public_key, user1_key))
        button_layout.addWidget(self.send_button_user2)

        layout.addLayout(button_layout)
        
        self.setLayout(layout)

    def send_message(self, sender, recipient_public_key, recipient_private_key):
        actual_message = self.input_text.text()
        self.input_text.clear()

        if not actual_message.strip():
            return

        generated_message = get_next_message()

        hashed_generated_message = hash_message(generated_message)

        retries = 0
        max_retries = 10
        while retries < max_retries:
            try:
                cursor.execute('INSERT INTO messages (actual_msg, generated_msg) VALUES (?, ?)', (actual_message, hashed_generated_message))
                conn.commit()
                break
            except sqlite3.IntegrityError:
                generated_message = get_next_message()
                hashed_generated_message = hash_message(generated_message)
                retries += 1

        if retries == max_retries:
            self.mitm_display.append("<b>Error:</b> Failed to insert unique generated message after multiple attempts.<br><br>")
            return

        encrypted_message = encrypt_message_rsa(generated_message, recipient_public_key)

        if sender == "User 1":
            self.user1_display.append(f"<b>{sender}:</b> {actual_message}<br><br>")
        else:
            self.user2_display.append(f"<b>{sender}:</b> {actual_message}<br><br>")
        
        self.mitm_display.append(f"<i>MITM intercepted:</i> {encrypted_message}<br><br>")

        try:
            decrypted_message_mitm = decrypt_message_rsa(encrypted_message, user1_key if sender == "User 2" else user2_key)
        except Exception as e:
            decrypted_message_mitm = "Incorrect decryption."

        self.mitm_display.append(f"<i>MITM decrypted:</i> {decrypted_message_mitm}<br><br>")

        decrypted_message = decrypt_message_rsa(encrypted_message, recipient_private_key)

        cursor.execute('SELECT actual_msg FROM messages WHERE generated_msg = ?', (hash_message(decrypted_message),))
        actual_message_row = cursor.fetchone()

        if actual_message_row:
            retrieved_actual_message = actual_message_row[0]

            if sender == "User 1":
                self.user2_display.append(f"<b>User 2 decrypted:</b> {retrieved_actual_message}<br><br>")
            else:
                self.user1_display.append(f"<b>User 1 decrypted:</b> {retrieved_actual_message}<br><br>")
        else:
            if sender == "User 1":
                self.user2_display.append(f"<b>User 2 decrypted:</b> Message not found<br><br>")
            else:
                self.user1_display.append(f"<b>User 1 decrypted:</b> Message not found<br><br>")

if __name__ == '__main__':
    reset_conversation_state()
    app = QApplication(sys.argv)
    ex = EncryptionApp()
    ex.show()
    sys.exit(app.exec_())