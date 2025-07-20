# VCC-Project
# 🌩️ Cloud-Native STaaS Uploader (AWS / Azure / GCP)

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Platform](https://img.shields.io/badge/platform-cross--platform-lightgrey)
![Cloud](https://img.shields.io/badge/cloud-multicloud-success)

A cross-platform **PyQt5 GUI application** that allows users to upload files and folders to **Amazon S3**, **Azure Blob**, and **Google Cloud Storage (GCS)** — all from a single intuitive interface.

> Developed as part of a Ph.D. research project at **IIT** on *Cloud-native Storage-as-a-Service (STaaS)*.

---

## 🚀 Features

- ✅ One-click upload to **AWS S3**, **Azure Blob**, or **Google Cloud Storage**
- 🔐 Encrypted credential management using Fernet
- 💾 Local profile storage for reuse
- 📂 Upload files and folders with real-time progress
- 🔄 Cloud provider switching with full logging
- 💡 Minimal dependencies, fully open-source

---

---

## 📁 Project Structure

- s3_uploader.py # Main GUI application
- requirements.txt # Python dependencies
- README.md # This file


---

## 🛠️ Technologies Used

| Category       | Tools/Services |
|----------------|----------------|
| GUI            | PyQt5          |
| AWS Storage    | Boto3 (S3)     |
| Azure Storage  | Azure SDK (Blob Storage) |
| GCP Storage    | Google Cloud SDK (Cloud Storage) |
| Security       | `cryptography` (Fernet encryption) |
| Scripting      | Python 3.8+    |

---

## ✅ Prerequisites

- Python 3.8+
- `pip` installed
- Cloud accounts for AWS / Azure / GCP
- GCP Service Account JSON file
- Azure Blob Storage connection string

---

## 🔧 Installation

```bash
# Clone this repository
git clone https://github.com/<your-username>/cloud-staas-gui.git
cd cloud-staas-gui

# Install dependencies
pip install -r requirements.txt

# Run the app
python s3_uploader.py

🔐 Cloud Credential Setup
AWS
Use Create AWS Connection

Enter Access Key, Secret Key, Region

Secure with a password (locally encrypted)

Azure
Use Create Azure Connection

Paste your Azure Blob connection string and container

Saved locally as a JSON profile

GCP
Use Create GCS Connection

Browse to your Service Account JSON

Provide the GCS bucket name

Profile saved locally for reuse

🧠 How it Works
Select a cloud provider from the dropdown

Load or create a connection profile

Select files/folders to upload

Click the upload button and monitor logs & progress

🧪 Testing Scenarios
Upload small & large files to all 3 providers

Test encrypted credential loading and profile reuse

Simulate invalid profiles to verify error handling

🙌 Contributions
Open to bug reports, feature requests, and pull requests!
Feel free to fork and enhance the app.


Let me know if you’d like:
- A live demo badge  
- `screenshot.gif` with animations  
- Separate wiki/docs folder setup

Ready to assist!
