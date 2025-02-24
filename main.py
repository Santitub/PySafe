import sys
import os
import threading
import secrets
import string
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, 
                            QMessageBox, QInputDialog, QHeaderView, QAbstractItemView, 
                            QToolBar, QAction, QStatusBar, QDialog, QDialogButtonBox, 
                            QFormLayout)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QIcon, QPixmap, QPalette, QColor

from funciones.password_manager import PasswordManager
from funciones.otp_manager import OTPManager

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

STYLESHEET = """
QMainWindow {
    background-color: #2D2D2D;
}

QWidget {
    background-color: #2D2D2D;
    color: #FFFFFF;
    font-family: 'Segoe UI';
    font-size: 12px;
}

QLineEdit {
    background-color: #404040;
    border: 1px solid #555555;
    border-radius: 4px;
    padding: 6px;
    min-width: 250px;
}

QLineEdit:focus {
    border: 1px solid #0078D4;
}

QPushButton {
    background-color: #0078D4;
    color: #FFFFFF;
    border: none;
    border-radius: 4px;
    padding: 8px 16px;
    min-width: 80px;
}

QPushButton:hover {
    background-color: #006CBC;
}

QPushButton:pressed {
    background-color: #005FA3;
}

QTableWidget {
    background-color: #404040;
    border: none;
    alternate-background-color: #4A4A4A;
    selection-background-color: #0078D4;
    gridline-color: #555555;
}

QHeaderView::section {
    background-color: #333333;
    color: #FFFFFF;
    padding: 6px;
    border: none;
}

QTabWidget::pane {
    border: none;
}

QTabBar::tab {
    background: #333333;
    color: #FFFFFF;
    padding: 8px 16px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}

QTabBar::tab:selected {
    background: #0078D4;
}

QDialog {
    background-color: #2D2D2D;
}

QLabel#title {
    font-size: 24px;
    font-weight: bold;
    color: #FFFFFF;
    padding: 16px 0;
}
"""

def load_icon(icon_name):
    icon_path = os.path.join(BASE_DIR, 'assets', icon_name)
    return QIcon(icon_path) if os.path.exists(icon_path) else QIcon()

class LoginWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.pm = PasswordManager()
        self.otp = OTPManager()
        self.setStyleSheet(STYLESHEET)
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('PySafe - Login')
        self.setWindowIcon(load_icon('logo.png'))
        self.setGeometry(300, 300, 480, 400)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setAlignment(Qt.AlignCenter)

        # Logo y título
        logo = QLabel()
        pixmap = QPixmap(os.path.join(BASE_DIR, 'assets', 'logo.png'))
        if not pixmap.isNull():
            logo.setPixmap(pixmap.scaled(80, 80, Qt.KeepAspectRatio))
        logo.setAlignment(Qt.AlignCenter)

        title = QLabel('PySafe Password Manager')
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #FFFFFF;")

        # Contenido
        self.content_widget = QWidget()
        content_layout = QVBoxLayout(self.content_widget)
        content_layout.setContentsMargins(40, 20, 40, 20)

        if not self.pm.is_master_password_set():
            self.show_initial_setup(content_layout)
        else:
            self.show_login_form(content_layout)

        layout.addWidget(logo)
        layout.addWidget(title)
        layout.addWidget(self.content_widget)

    def show_initial_setup(self, layout):
        self.email_input = self.create_input_field('Correo electrónico:')
        self.password_input = self.create_input_field('Contraseña maestra:', True)
        self.confirm_input = self.create_input_field('Confirmar contraseña:', True)

        btn_submit = QPushButton('Configurar cuenta')
        btn_submit.clicked.connect(self.handle_initial_setup)
        layout.addWidget(self.email_input)
        layout.addWidget(self.password_input)
        layout.addWidget(self.confirm_input)
        layout.addWidget(btn_submit)

    def show_login_form(self, layout):
        self.password_input = self.create_input_field('Contraseña maestra:', True)
        btn_login = QPushButton('Iniciar sesión')
        btn_login.clicked.connect(self.handle_login)
        layout.addWidget(self.password_input)
        layout.addWidget(btn_login)

    def create_input_field(self, label, is_password=False):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        lbl = QLabel(label)
        input_field = QLineEdit()
        input_field.setEchoMode(QLineEdit.Password) if is_password else None
        input_field.setStyleSheet("padding: 8px; border-radius: 4px;")
        layout.addWidget(lbl)
        layout.addWidget(input_field)
        return widget

    def handle_initial_setup(self):
        email = self.email_input.findChild(QLineEdit).text().strip()
        password = self.password_input.findChild(QLineEdit).text()
        confirm = self.confirm_input.findChild(QLineEdit).text()

        if not self.validate_email(email):
            QMessageBox.critical(self, 'Error', 'Correo electrónico inválido')
            return

        if password != confirm:
            QMessageBox.critical(self, 'Error', 'Las contraseñas no coinciden')
            return

        if len(password) < 8:
            QMessageBox.critical(self, 'Error', 'La contraseña debe tener al menos 8 caracteres')
            return

        try:
            self.pm.set_master_password(password, email)
            self.send_otp_and_login(email, password)
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Error: {str(e)}')

    def handle_login(self):
        password = self.password_input.findChild(QLineEdit).text()
        if not self.pm.verify_master_password(password):
            QMessageBox.critical(self, 'Error', 'Contraseña incorrecta')
            return

        try:
            email = self.pm.get_email()
            self.send_otp_and_login(email, password)
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Error al obtener el email: {str(e)}')

    def send_otp_and_login(self, email, password):
        otp = self.otp.generate_otp()
        threading.Thread(target=self.otp.send_otp_email, args=(email, otp)).start()
        self.show_otp_dialog(email, password)

    def show_otp_dialog(self, email, password):
        otp, ok = QInputDialog.getText(self, 'Verificación OTP', 
                                      f'Ingrese el código enviado a {email}:')
        if ok and self.otp.verify_otp(email, otp):
            self.open_main_app(password)
        else:
            QMessageBox.critical(self, 'Error', 'Código OTP inválido o expirado')

    def open_main_app(self, password):
        self.main_app = MainApp(password)
        self.main_app.show()
        self.close()

    def validate_email(self, email):
        return '@' in email and '.' in email.split('@')[-1]

class MainApp(QMainWindow):
    def __init__(self, master_password):
        super().__init__()
        self.pm = PasswordManager()
        self.master_password = master_password
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('PySafe - Administrador de Contraseñas')
        self.setWindowIcon(load_icon('logo.png'))
        self.setGeometry(100, 100, 1024, 600)
        self.setStyleSheet(STYLESHEET)

        # Toolbar
        toolbar = QToolBar()
        toolbar.setIconSize(QSize(28, 28))
        
        # Acciones
        self.add_action = QAction(load_icon('add.png'), 'Agregar', self)
        self.add_action.triggered.connect(self.show_add_dialog)
        
        self.edit_action = QAction(load_icon('edit.png'), 'Editar', self)
        self.edit_action.triggered.connect(self.edit_password)
        
        self.delete_action = QAction(load_icon('delete.png'), 'Eliminar', self)
        self.delete_action.triggered.connect(self.delete_password)
        
        toolbar.addActions([self.add_action, self.edit_action, self.delete_action])
        self.addToolBar(toolbar)

        # Tabla principal
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(['Servicio', 'Usuario', 'Contraseña'])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)

        # Barra de búsqueda
        search_widget = QWidget()
        search_layout = QHBoxLayout(search_widget)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText('Buscar contraseñas...')
        self.search_input.textChanged.connect(self.filter_table)
        search_layout.addWidget(self.search_input)

        # Layout principal
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        main_layout.addWidget(search_widget)
        main_layout.addWidget(self.table)
        self.setCentralWidget(central_widget)

        # Barra de estado
        self.statusBar().showMessage('Listo')
        
        self.load_passwords()

    def load_passwords(self):
        try:
            passwords = self.pm.get_passwords(self.master_password)
            self.table.setRowCount(len(passwords))
            
            for row, (service, data) in enumerate(passwords.items()):
                self.table.setItem(row, 0, QTableWidgetItem(service))
                self.table.setItem(row, 1, QTableWidgetItem(data['username']))
                self.table.setItem(row, 2, QTableWidgetItem(data['password']))
                
            self.statusBar().showMessage(f'{len(passwords)} contraseñas cargadas', 3000)
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Error al cargar contraseñas: {str(e)}')

    def show_add_dialog(self):
        dialog = PasswordDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            service, username, password = dialog.get_data()
            if not service or not password:
                QMessageBox.warning(self, 'Advertencia', 'Servicio y contraseña son requeridos')
                return
                
            try:
                self.pm.add_password(self.master_password, service, username, password)
                self.load_passwords()
                self.statusBar().showMessage('Contraseña agregada exitosamente', 3000)
            except Exception as e:
                QMessageBox.critical(self, 'Error', f'Error al guardar: {str(e)}')

    def edit_password(self):
        selected_row = self.table.currentRow()
        if selected_row == -1:
            QMessageBox.warning(self, 'Advertencia', 'Selecciona una contraseña para editar')
            return
            
        try:
            service = self.table.item(selected_row, 0).text()
            passwords = self.pm.get_passwords(self.master_password)
            current_data = passwords[service]
            
            dialog = PasswordDialog(self)
            dialog.set_data(service, current_data['username'], current_data['password'])
            
            if dialog.exec_() == QDialog.Accepted:
                new_service, username, password = dialog.get_data()
                
                if service != new_service:
                    del passwords[service]
                passwords[new_service] = {'username': username, 'password': password}
                
                self.pm.save_passwords(self.master_password, passwords)
                self.load_passwords()
                self.statusBar().showMessage('Contraseña actualizada exitosamente', 3000)
                
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Error al editar: {str(e)}')

    def delete_password(self):
        selected_row = self.table.currentRow()
        if selected_row == -1:
            QMessageBox.warning(self, 'Advertencia', 'Selecciona una contraseña para eliminar')
            return
            
        try:
            service = self.table.item(selected_row, 0).text()
            confirm = QMessageBox.question(
                self, 'Confirmar', 
                f'¿Eliminar contraseña para "{service}"?',
                QMessageBox.Yes | QMessageBox.No
            )
            
            if confirm == QMessageBox.Yes:
                passwords = self.pm.get_passwords(self.master_password)
                del passwords[service]
                self.pm.save_passwords(self.master_password, passwords)
                self.load_passwords()
                self.statusBar().showMessage('Contraseña eliminada exitosamente', 3000)
                
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Error al eliminar: {str(e)}')

    def filter_table(self):
        search_text = self.search_input.text().lower()
        for row in range(self.table.rowCount()):
            service = self.table.item(row, 0).text().lower()
            username = self.table.item(row, 1).text().lower()
            password = self.table.item(row, 2).text().lower()
            match = any(search_text in text for text in [service, username, password])
            self.table.setRowHidden(row, not match)


class PasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Gestión de Contraseña')
        self.setWindowIcon(load_icon('key.png'))
        self.init_ui()

    def init_ui(self):
        layout = QFormLayout(self)
        
        # Campos de entrada
        self.service_input = QLineEdit()
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        
        # Botones de acción
        self.btn_generate = QPushButton('Generar contraseña segura')
        self.btn_generate.clicked.connect(self.generate_password)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.validate_inputs)
        button_box.rejected.connect(self.reject)

        # Diseño
        layout.addRow('Servicio:', self.service_input)
        layout.addRow('Usuario (opcional):', self.username_input)
        layout.addRow('Contraseña:', self.password_input)
        layout.addRow(self.btn_generate)
        layout.addRow(button_box)

    def generate_password(self):
        characters = string.ascii_letters + string.digits + "!@#$%^&*()_-+="
        password = ''.join(secrets.choice(characters) for _ in range(16))
        self.password_input.setText(password)
        self.password_input.setEchoMode(QLineEdit.Normal)

    def set_data(self, service, username, password):
        self.service_input.setText(service)
        self.username_input.setText(username)
        self.password_input.setText(password)

    def validate_inputs(self):
        if not self.service_input.text().strip():
            QMessageBox.warning(self, 'Advertencia', 'El campo Servicio es requerido')
            return
            
        if not self.password_input.text().strip():
            QMessageBox.warning(self, 'Advertencia', 'El campo Contraseña es requerido')
            return
            
        self.accept()

    def get_data(self):
        return (
            self.service_input.text().strip(),
            self.username_input.text().strip(),
            self.password_input.text().strip()
        )

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Configurar paleta de colores
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(45, 45, 45))
    palette.setColor(QPalette.WindowText, Qt.white)
    app.setPalette(palette)
    
    window = LoginWindow()
    window.show()
    sys.exit(app.exec_())