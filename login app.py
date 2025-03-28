import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QMessageBox, QVBoxLayout, QDialog
)
from PyQt5.QtGui import QFont, QPixmap
from PyQt5.QtGui import QFont, QColor, QPalette
import sqlite3


def setup_database():
    conn = sqlite3.connect("users_secure.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

class RegisterDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Register")
        self.setGeometry(400, 200, 400, 300)

        layout = QVBoxLayout()

        self.username_label = QLabel("Username:")
        self.username_label.setFont(QFont("Arial", 12))
        self.username_label.setStyleSheet("color: #FF6347;")  # Tomato color
        layout.addWidget(self.username_label)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username")
        layout.addWidget(self.username_input)

        self.password_label = QLabel("Password:")
        self.password_label.setFont(QFont("Arial", 12))
        self.password_label.setStyleSheet("color: #FF6347;")  # Tomato color
        layout.addWidget(self.password_label)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        self.confirm_label = QLabel("Confirm Password:")
        self.confirm_label.setFont(QFont("Arial", 12))
        self.confirm_label.setStyleSheet("color: #FF6347;")  # Tomato color
        layout.addWidget(self.confirm_label)

        self.confirm_input = QLineEdit()
        self.confirm_input.setPlaceholderText("Confirm password")
        self.confirm_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.confirm_input)

        self.register_button = QPushButton("Register")
        self.register_button.setStyleSheet("color: white; background-color: #28a745;")  # Green button text
        self.register_button.clicked.connect(self.register_user)
        layout.addWidget(self.register_button)

        self.setLayout(layout)

    def register_user(self):
        username = self.username_input.text()
        password = self.password_input.text()
        confirm_password = self.confirm_input.text()

        if not username or not password:
            QMessageBox.warning(self, "Error", "All fields are required!")
            return

        if password != confirm_password:
            QMessageBox.warning(self, "Error", "Passwords do not match!")
            return

        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        conn = sqlite3.connect("users_secure.db")
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            QMessageBox.information(self, "Success", "Account created successfully!")
            self.close()
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, "Error", "Username already exists!")
        finally:
            conn.close()


class LoginApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Login App")
        self.setGeometry(300, 150, 500, 400)

        # Title label
        self.title_label = QLabel("Login", self)
        self.title_label.setFont(QFont("Rockwell", 24, QFont.Bold))
        self.title_label.setStyleSheet("color: #1e90ff;")  # Dodger blue color
        self.title_label.setGeometry(180, 20, 300, 50)

        # Username
        self.username_label = QLabel("Username:", self)
        self.username_label.setFont(QFont("Arial", 12))
        self.username_label.setStyleSheet("color: #FF6347;")  # Tomato color
        self.username_label.setGeometry(100, 100, 100, 30)

        self.username_input = QLineEdit(self)
        self.username_input.setGeometry(200, 100, 200, 30)
        self.username_input.setPlaceholderText("Enter username")

        # Password
        self.password_label = QLabel("Password:", self)
        self.password_label.setFont(QFont("Arial", 12))
        self.password_label.setStyleSheet("color: #FF6347;")  # Tomato color
        self.password_label.setGeometry(100, 150, 100, 30)

        self.password_input = QLineEdit(self)
        self.password_input.setGeometry(200, 150, 200, 30)
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.Password)

        # Login button
        self.login_button = QPushButton("Login", self)
        self.login_button.setGeometry(100, 220, 100, 40)
        self.login_button.setStyleSheet("color: white; background-color: #007bff;")  # Blue button text
        self.login_button.clicked.connect(self.login_user)

        # Register button
        self.register_button = QPushButton("Register", self)
        self.register_button.setGeometry(200, 220, 100, 40)
        self.register_button.setStyleSheet("color: white; background-color: #28a745;")  # Green button text
        self.register_button.clicked.connect(self.open_register_dialog)

        # Exit button
        self.exit_button = QPushButton("Exit", self)
        self.exit_button.setGeometry(300, 220, 100, 40)
        self.exit_button.setStyleSheet("color: white; background-color: #dc3545;")  # Red button text
        self.exit_button.clicked.connect(self.close_application)

    def login_user(self):
        username = self.username_input.text()
        password = self.password_input.text()

        conn = sqlite3.connect("users_secure.db")
        cursor = conn.cursor()

        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result and bcrypt.checkpw(password.encode(), result[0]):
            QMessageBox.information(self, "Success", f"Welcome, {username}!")
        else:
            QMessageBox.warning(self, "Error", "Invalid username or password!")

    def open_register_dialog(self):
        register_dialog = RegisterDialog()
        register_dialog.exec()

    def close_application(self):
        self.close()


if __name__ == "__main__":
    setup_database()
    app = QApplication(sys.argv)
    login_app = LoginApp()
    login_app.show()
    sys.exit(app.exec())
