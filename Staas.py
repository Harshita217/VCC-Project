import sys
import os
import threading
import time
import base64
import json
import boto3
import botocore
from google.cloud import storage
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QLabel,
    QFileDialog, QMessageBox, QProgressBar, QInputDialog, QTextEdit, QComboBox, QFrame, QGroupBox
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject
from PyQt5.QtGui import QFont, QColor, QPalette
from azure.storage.blob import BlobServiceClient

CRED_DIR = os.path.expanduser("~/.aws_pyqt_multi_creds")
os.makedirs(CRED_DIR, exist_ok=True)

AZURE_CONN_DIR = os.path.expanduser("~/.azure_pyqt_multi_conns")
os.makedirs(AZURE_CONN_DIR, exist_ok=True)

GCS_CONN_DIR = os.path.expanduser("~/.gcs_pyqt_multi_conns")
os.makedirs(GCS_CONN_DIR, exist_ok=True)

# GCP
def save_gcs_conn(profile_name, sa_path, bucket):
    data = {"sa_path": sa_path, "bucket": bucket}
    with open(os.path.join(GCS_CONN_DIR, f"{profile_name}.json"), "w") as f:
        json.dump(data, f)

def load_gcs_conn(profile_name):
    path = os.path.join(GCS_CONN_DIR, f"{profile_name}.json")
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        return json.load(f)

def list_gcs_conns():
    return [f[:-5] for f in os.listdir(GCS_CONN_DIR) if f.endswith(".json")]


# --- Credential Encryption ---
def generate_key(password: str) -> bytes:
    return base64.urlsafe_b64encode(password.encode('utf-8').ljust(32)[:32])

def save_creds(profile_name, access_key, secret_key, region, password):
    key = generate_key(password)
    fernet = Fernet(key)
    data = f"{access_key}\n{secret_key}\n{region}".encode()
    encrypted = fernet.encrypt(data)
    with open(os.path.join(CRED_DIR, f"{profile_name}.cred"), "wb") as f:
        f.write(encrypted)

def load_creds(profile_name, password):
    path = os.path.join(CRED_DIR, f"{profile_name}.cred")
    if not os.path.exists(path):
        return None
    key = generate_key(password)
    fernet = Fernet(key)
    try:
        with open(path, "rb") as f:
            encrypted = f.read()
        decrypted = fernet.decrypt(encrypted).decode()
        return decrypted.splitlines()
    except Exception:
        return None

def list_profiles():
    return [f[:-5] for f in os.listdir(CRED_DIR) if f.endswith(".cred")]

def save_azure_conn(profile_name, conn_str, container):
    data = {"conn_str": conn_str, "container": container}
    with open(os.path.join(AZURE_CONN_DIR, f"{profile_name}.json"), "w") as f:
        json.dump(data, f)

def load_azure_conn(profile_name):
    path = os.path.join(AZURE_CONN_DIR, f"{profile_name}.json")
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        return json.load(f)

def list_azure_conns():
    return [f[:-5] for f in os.listdir(AZURE_CONN_DIR) if f.endswith(".json")]

# --- Progress Callback ---
class ProgressPercentage(QObject):
    progress_changed = pyqtSignal(int)

    def __init__(self, filename):
        super().__init__()
        self._filename = filename
        self._size = float(os.path.getsize(filename))
        self._seen_so_far = 0

    def __call__(self, bytes_amount):
        self._seen_so_far += bytes_amount
        percentage = int((self._seen_so_far / self._size) * 100)
        self.progress_changed.emit(percentage)

# --- Main App ---
class S3Uploader(QWidget):
    message_signal = pyqtSignal(str, bool)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Free Cloud Uploader - aws/gcp/azure")
        self.resize(600, 600)
        self.setStyleSheet("""
                QWidget {
                    font-family: Segoe UI, Arial;
                    font-size: 11pt;
                    background-color: #1e1e1e;
                    color: #dcdcdc;
                }
                QPushButton {
                    padding: 8px 14px;
                    background-color: #0078d7;
                    border-radius: 5px;
                    color: white;
                }
                QPushButton:hover {
                    background-color: #005a9e;
                }
                QLineEdit, QTextEdit, QComboBox {
                    padding: 6px;
                    border-radius: 4px;
                    background-color: #2d2d30;
                    border: 1px solid #444;
                }
                QProgressBar {
                    border-radius: 5px;
                    text-align: center;
                    background-color: #2d2d30;
                }
                QProgressBar::chunk {
                    background-color: #0a84ff;
                }
                QGroupBox {
                    margin-top: 15px;
                    border: 1px solid #444;
                    border-radius: 5px;
                    padding: 10px;
                    font-weight: bold;
                    color: #fff;
                }
            """)

        self.access_key = None
        self.secret_key = None
        self.region = None
        self.s3 = None
        self.bucket = None

        self.files_to_upload = []

        # Azure fields
        self.azure_conn_str = ""
        self.azure_container = ""

        self.init_ui()
        self.message_signal.connect(self._handle_message)
        self.load_profiles()

    def init_ui(self):
        layout = QVBoxLayout()
        toolbar = QHBoxLayout()
        save_cred_btn = QPushButton("Create AWS Connection")
        save_cred_btn.clicked.connect(self.save_credentials_dialog)
        toolbar.addWidget(save_cred_btn)

        save_azure_btn = QPushButton("Create Azure Connection")
        save_azure_btn.clicked.connect(self.save_azure_connection_dialog)
        toolbar.addWidget(save_azure_btn)

        gcs_save_btn = QPushButton("Create GCS Connection")
        gcs_save_btn.clicked.connect(self.save_gcs_connection_dialog)
        toolbar.addWidget(gcs_save_btn)

        load_btn = QPushButton("Load AWS Connection")
        load_btn.clicked.connect(self.load_selected_profile)
        toolbar.addWidget(load_btn)

        load_azure_btn = QPushButton("Load Azure Connection")
        load_azure_btn.clicked.connect(self.load_selected_azure_conn)
        toolbar.addWidget(load_azure_btn)

        gcs_load_btn = QPushButton("Load GCS Connection")
        gcs_load_btn.clicked.connect(self.load_selected_gcs_conn)
        toolbar.addWidget(gcs_load_btn)

        reset_btn = QPushButton("Reset App")
        reset_btn.clicked.connect(self.reset_fields)
        toolbar.addWidget(reset_btn)

        toolbar.addStretch()
        layout.addLayout(toolbar)

        # --- Cloud Provider Dropdown ---
        provider_layout = QHBoxLayout()
        provider_label = QLabel("Cloud Provider:")
        provider_layout.addWidget(provider_label)
        self.provider_selector = QComboBox()
        self.provider_selector.addItems(["AWS S3", "Azure Blob", "Google Cloud Storage"])
        provider_layout.addWidget(self.provider_selector)
        provider_layout.addStretch()
        layout.addLayout(provider_layout)

        # --- AWS fields ---
        self.aws_profile_label = QLabel("AWS Profile:")
        layout.addWidget(self.aws_profile_label)
        self.profile_selector = QComboBox()
        layout.addWidget(self.profile_selector)

        self.s3_bucket_label = QLabel("S3 Bucket Name:")
        layout.addWidget(self.s3_bucket_label)
        self.bucket_input = QLineEdit()
        self.bucket_input.setPlaceholderText("e.g. my-bucket-name")
        layout.addWidget(self.bucket_input)

        # --- Azure fields ---
        self.azure_conn_label = QLabel("Azure Connection Profile:")
        layout.addWidget(self.azure_conn_label)
        self.azure_profile_selector = QComboBox()
        layout.addWidget(self.azure_profile_selector)

        self.azure_conn_input = QLineEdit()
        self.azure_conn_input.setPlaceholderText("Paste Azure Storage connection string")
        layout.addWidget(self.azure_conn_input)

        self.azure_container_label = QLabel("Azure Container Name:")
        layout.addWidget(self.azure_container_label)
        self.azure_container_input = QLineEdit()
        self.azure_container_input.setPlaceholderText("e.g. my-container")
        layout.addWidget(self.azure_container_input)
        
############################################################################################################

        self.gcs_conn_label = QLabel("GCS Connection Profile:")
        layout.addWidget(self.gcs_conn_label)
        self.gcs_profile_selector = QComboBox()
        layout.addWidget(self.gcs_profile_selector)

        self.gcs_key_input = QLineEdit()
        self.gcs_key_input.setPlaceholderText("Path to GCS Service Account JSON")
        layout.addWidget(self.gcs_key_input)

        self.gcs_bucket_input = QLineEdit()
        self.gcs_bucket_input.setPlaceholderText("GCS Bucket Name")
        layout.addWidget(self.gcs_bucket_input)

        btn_layout = QHBoxLayout()
        file_btn = QPushButton("Select Files")
        file_btn.clicked.connect(self.select_files)
        btn_layout.addWidget(file_btn)

        folder_btn = QPushButton("Select Folder")
        folder_btn.clicked.connect(self.select_folder)
        btn_layout.addWidget(folder_btn)
        layout.addLayout(btn_layout)

        layout.addWidget(QLabel("Files to Upload:"))
        self.files_display = QLineEdit()
        self.files_display.setReadOnly(True)
        layout.addWidget(self.files_display)

        self.progress = QProgressBar()
        layout.addWidget(self.progress)

        self.total_time_label = QLabel("Total upload time: 0.00 seconds")
        self.total_time_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.total_time_label)

        # --- Upload Buttons ---
        self.upload_btn = QPushButton("Upload to AWS S3")
        self.upload_btn.clicked.connect(self.start_upload)
        layout.addWidget(self.upload_btn)

        self.azure_upload_btn = QPushButton("Upload to Azure Blob")
        self.azure_upload_btn.clicked.connect(self.start_azure_upload)
        layout.addWidget(self.azure_upload_btn)

        self.gcs_upload_btn = QPushButton("Upload to GCS")
        self.gcs_upload_btn.clicked.connect(self.start_gcs_upload)
        layout.addWidget(self.gcs_upload_btn)


        layout.addWidget(QLabel("Logs:"))
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setMinimumHeight(150)
        layout.addWidget(self.log_display)

        # Connect dropdown to handler
        self.provider_selector.currentIndexChanged.connect(self.update_provider_fields)
        self.update_provider_fields()
        self.load_profiles()
        self.load_azure_profiles()
        self.load_gcs_profiles()
        self.setLayout(layout)

    def save_azure_connection_dialog(self):
        conn_str, ok1 = QInputDialog.getText(self, "Azure Connection String", "Enter Azure Storage connection string:")
        if not ok1 or not conn_str:
            return
        container, ok2 = QInputDialog.getText(self, "Azure Container Name", "Enter Azure Container Name:")
        if not ok2 or not container:
            return
        profile_name, ok3 = QInputDialog.getText(self, "Profile Name", "Enter a name for this Azure connection:")
        if not ok3 or not profile_name:
            return
        save_azure_conn(profile_name, conn_str, container)
        QMessageBox.information(self, "Saved", f"Azure connection saved as profile '{profile_name}'.")
        self.load_azure_profiles()

    def load_azure_profiles(self):
        self.azure_profile_selector.clear()
        self.azure_profile_selector.addItems(list_azure_conns())

    def load_selected_azure_conn(self):
        profile = self.azure_profile_selector.currentText()
        if not profile:
            return
        data = load_azure_conn(profile)
        if data:
            self.azure_conn_input.setText(data["conn_str"])
            self.azure_container_input.setText(data["container"])
            self.log_display.append(f"✅ Azure profile '{profile}' loaded successfully.")
        else:
            QMessageBox.warning(self, "Failed", "Could not load Azure connection profile.")

    # GCP
    def save_gcs_connection_dialog(self):
        sa_path, ok1 = QInputDialog.getText(self, "GCS Service Account", "Path to service account JSON:")
        if not ok1 or not sa_path:
            return
        bucket, ok2 = QInputDialog.getText(self, "GCS Bucket Name", "Enter bucket name:")
        if not ok2 or not bucket:
            return
        profile_name, ok3 = QInputDialog.getText(self, "Profile Name", "Enter name for this GCS profile:")
        if not ok3 or not profile_name:
            return
        save_gcs_conn(profile_name, sa_path, bucket)
        QMessageBox.information(self, "Saved", f"GCS connection saved as '{profile_name}'.")
        self.load_gcs_profiles()

    def load_selected_gcs_conn(self):
        profile = self.gcs_profile_selector.currentText()
        if not profile:
            return
        data = load_gcs_conn(profile)
        if data:
            self.gcs_key_input.setText(data["sa_path"])
            self.gcs_bucket_input.setText(data["bucket"])
            self.log_display.append(f"✅ GCS profile '{profile}' loaded successfully.")
        else:
            QMessageBox.warning(self, "Failed", "Could not load GCS profile.")

    def load_gcs_profiles(self):
        self.gcs_profile_selector.clear()
        self.gcs_profile_selector.addItems(list_gcs_conns())

    def update_provider_fields(self):
        provider = self.provider_selector.currentText()
        is_aws = provider == "AWS S3"
        is_azure = provider == "Azure Blob"
        is_gcs = provider == "Google Cloud Storage"

        # AWS fields
        self.aws_profile_label.setVisible(is_aws)
        self.profile_selector.setVisible(is_aws)
        self.s3_bucket_label.setVisible(is_aws)
        self.bucket_input.setVisible(is_aws)
        self.upload_btn.setVisible(is_aws)

        # Azure fields
        self.azure_conn_label.setVisible(is_azure)
        self.azure_profile_selector.setVisible(is_azure)
        self.azure_conn_input.setVisible(is_azure)
        self.azure_container_label.setVisible(is_azure)
        self.azure_container_input.setVisible(is_azure)
        self.azure_upload_btn.setVisible(is_azure)

        # GCS fields
        self.gcs_conn_label.setVisible(is_gcs)
        self.gcs_profile_selector.setVisible(is_gcs)
        self.gcs_key_input.setVisible(is_gcs)
        self.gcs_bucket_input.setVisible(is_gcs)
        self.gcs_upload_btn.setVisible(is_gcs)


    def select_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        if files:
            self.files_to_upload.extend(files)
            self.update_files_display()

    def select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder:
            for root, _, files in os.walk(folder):
                for file in files:
                    self.files_to_upload.append(os.path.join(root, file))
            self.update_files_display()

    def update_files_display(self):
        if not self.files_to_upload:
            self.files_display.setText("")
        elif len(self.files_to_upload) <= 3:
            self.files_display.setText(", ".join(os.path.basename(f) for f in self.files_to_upload))
        else:
            first_three = ", ".join(os.path.basename(f) for f in self.files_to_upload[:3])
            self.files_display.setText(f"{first_three}, ... +{len(self.files_to_upload)-3} more")

    def load_selected_profile(self):
        profile = self.profile_selector.currentText()
        if not profile:
            return
        password, ok = QInputDialog.getText(self, "Enter Password", f"Password for profile '{profile}':", QLineEdit.Password)
        if ok and password:
            creds = load_creds(profile, password)
            if creds:
                self.access_key, self.secret_key, self.region = creds
                self.log_display.append(f"✅ Profile '{profile}' loaded successfully.")
            else:
                QMessageBox.warning(self, "Failed", "Invalid password or corrupted credential file.")

    def load_profiles(self):
        self.profile_selector.clear()
        self.profile_selector.addItems(list_profiles())

    def save_credentials_dialog(self):
        access_key, ok1 = QInputDialog.getText(self, "AWS Access Key ID", "Enter AWS Access Key ID:")
        if not ok1 or not access_key:
            return
        secret_key, ok2 = QInputDialog.getText(self, "AWS Secret Access Key", "Enter AWS Secret Access Key:", QLineEdit.Password)
        if not ok2 or not secret_key:
            return
        region, ok3 = QInputDialog.getText(self, "AWS Region", "Enter AWS Region (e.g. us-east-1):")
        if not ok3 or not region:
            return
        profile_name, ok4 = QInputDialog.getText(self, "Profile Name", "Enter a name for this profile:")
        if not ok4 or not profile_name:
            return
        password, ok5 = QInputDialog.getText(self, "Set Password", "Enter a password to encrypt credentials:", QLineEdit.Password)
        if not ok5 or not password:
            return
        save_creds(profile_name, access_key, secret_key, region, password)
        QMessageBox.information(self, "Saved", f"AWS credentials saved as profile '{profile_name}'.")
        self.load_profiles()

    def start_upload(self):
        if not self.access_key or not self.secret_key or not self.region:
            QMessageBox.warning(self, "Error", "No AWS credentials loaded.")
            return
        bucket = self.bucket_input.text().strip()
        if not bucket:
            QMessageBox.warning(self, "Error", "Please enter an S3 bucket name.")
            return
        if not self.files_to_upload:
            QMessageBox.warning(self, "Error", "No files selected for upload.")
            return

        self.progress.setValue(0)
        self.total_time_label.setText("Total upload time: 0.00 seconds")
        self.log_display.append("🚀 Starting upload...")

        def upload_files():
            start_time = time.time()
            try:
                s3 = boto3.client(
                    "s3",
                    aws_access_key_id=self.access_key,
                    aws_secret_access_key=self.secret_key,
                    region_name=self.region,
                )
                total_files = len(self.files_to_upload)
                for idx, file_path in enumerate(self.files_to_upload, 1):
                    file_name = os.path.basename(file_path)
                    self.message_signal.emit(f"Uploading {file_name}...", True)
                    progress_callback = ProgressPercentage(file_path)
                    progress_callback.progress_changed.connect(self.progress.setValue)
                    try:
                        s3.upload_file(
                            file_path,
                            bucket,
                            file_name,
                            Callback=progress_callback,
                        )
                        self.message_signal.emit(f"✅ Uploaded {file_name}", True)
                    except Exception as e:
                        self.message_signal.emit(f"❌ Failed to upload {file_name}: {e}", False)
                    self.progress.setValue(int((idx / total_files) * 100))
                elapsed = time.time() - start_time
                self.total_time_label.setText(f"Total upload time: {elapsed:.2f} seconds")
                self.message_signal.emit("🎉 Upload finished.", True)
            except Exception as e:
                self.message_signal.emit(f"❌ Upload error: {e}", False)
        threading.Thread(target=upload_files, daemon=True).start()

    def start_azure_upload(self):
        conn_str = self.azure_conn_input.text().strip()
        container = self.azure_container_input.text().strip()
        if not conn_str or not container:
            QMessageBox.warning(self, "Error", "Please enter Azure connection string and container name.")
            return
        if not self.files_to_upload:
            QMessageBox.warning(self, "Error", "No files selected for upload.")
            return

        self.progress.setValue(0)
        self.total_time_label.setText("Total upload time: 0.00 seconds")
        self.log_display.append("🚀 Starting Azure upload...")

        def upload_files():
            start_time = time.time()
            try:
                blob_service_client = BlobServiceClient.from_connection_string(conn_str)
                container_client = blob_service_client.get_container_client(container)
                total_files = len(self.files_to_upload)
                for idx, file_path in enumerate(self.files_to_upload, 1):
                    file_name = os.path.basename(file_path)
                    self.message_signal.emit(f"Uploading {file_name} to Azure...", True)
                    try:
                        with open(file_path, "rb") as data:
                            container_client.upload_blob(name=file_name, data=data, overwrite=True)
                        self.message_signal.emit(f"✅ Uploaded {file_name} to Azure", True)
                    except Exception as e:
                        self.message_signal.emit(f"❌ Failed to upload {file_name} to Azure: {e}", False)
                    self.progress.setValue(int((idx / total_files) * 100))
                elapsed = time.time() - start_time
                self.total_time_label.setText(f"Total upload time: {elapsed:.2f} seconds")
                self.message_signal.emit("🎉 Azure upload finished.", True)
            except Exception as e:
                self.message_signal.emit(f"❌ Azure upload error: {e}", False)
        threading.Thread(target=upload_files, daemon=True).start()

    # gcp
    def start_gcs_upload(self):
        sa_path = self.gcs_key_input.text().strip()
        bucket_name = self.gcs_bucket_input.text().strip()
        if not sa_path or not bucket_name:
            QMessageBox.warning(self, "Error", "Please provide service account path and bucket name.")
            return
        if not self.files_to_upload:
            QMessageBox.warning(self, "Error", "No files selected.")
            return

        self.progress.setValue(0)
        self.total_time_label.setText("Total upload time: 0.00 seconds")
        self.log_display.append("🚀 Starting GCS upload...")

        def upload_files():
            start_time = time.time()
            try:
                client = storage.Client.from_service_account_json(sa_path)
                bucket = client.bucket(bucket_name)
                total_files = len(self.files_to_upload)
                for idx, file_path in enumerate(self.files_to_upload, 1):
                    file_name = os.path.basename(file_path)
                    self.message_signal.emit(f"Uploading {file_name} to GCS...", True)
                    try:
                        blob = bucket.blob(file_name)
                        blob.upload_from_filename(file_path)
                        self.message_signal.emit(f"✅ Uploaded {file_name} to GCS", True)
                    except Exception as e:
                        self.message_signal.emit(f"❌ Failed to upload {file_name} to GCS: {e}", False)
                    self.progress.setValue(int((idx / total_files) * 100))
                elapsed = time.time() - start_time
                self.total_time_label.setText(f"Total upload time: {elapsed:.2f} seconds")
                self.message_signal.emit("🎉 GCS upload finished.", True)
            except Exception as e:
                self.message_signal.emit(f"❌ GCS upload error: {e}", False)

        threading.Thread(target=upload_files, daemon=True).start()


    def reset_fields(self):
        self.access_key = None
        self.secret_key = None
        self.region = None
        self.s3 = None
        self.bucket = None
        self.files_to_upload = []
        self.profile_selector.setCurrentIndex(-1)
        self.bucket_input.clear()
        self.files_display.clear()
        self.progress.setValue(0)
        self.total_time_label.setText("Total upload time: 0.00 seconds")
        self.log_display.clear()

    def _handle_message(self, message, success):
        color = "green" if success else "red"
        self.log_display.append(f'<span style="color:{color};">{message}</span>')

# main entry point
if __name__ == "__main__":
    app = QApplication(sys.argv)
    uploader = S3Uploader()
    uploader.show()
    sys.exit(app.exec_())
