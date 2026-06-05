# File Cipher 🔐

A sleek, modern, and lightweight desktop application built in Python using **CustomTkinter** that allows users to securely encrypt any file type (documents, videos, databases, etc.) using industry-standard AES-256 cryptography.

Developed with a non-blocking multithreaded architecture, the application handles large files smoothly without freezing, providing real-time percentage progress updates.

---

## ✨ Features

* **Military-Grade Security:** Utilizes AES-256 (CTR mode) powered by a 512-bit password derivation pipeline (PBKDF2 with SHA-512).
* **Enforced Password Hygiene:** Validates strict password criteria (minimum 8 characters, uppercase, lowercase, numbers, and symbols) to prevent brute-force vulnerabilities.
* **Asynchronous Processing:** Powered by Python `threading` so the interface remains fully responsive ("Not Responding" bugs are eliminated).
* **Smart Naming Conventions:** Automatically appends `_enc` and `.enc` to encrypted outputs, and cleanly restores original naming conventions with a `_dec` suffix upon decryption.
* **Modern UI/UX:** A clean, dark-themed user interface featuring modern rounded components, hover animations, centered window execution, and fluid tracking bars.

---

## 🛠️ Cryptographic Architecture

To provide maximum security, the core backend relies on the `cryptography` library following strict security engineering guidelines:

1.  **Key Derivation:** Your plain text password is mixed with a cryptographically secure random 16-byte `SALT` using **PBKDF2** running **100,000 iterations** of **HMAC-SHA512** to generate a rigid 256-bit key.
2.  **Stream Ciphering:** Employs **AES-256-CTR** paired with a random 16-byte Initialization Vector (`IV`) to securely chunk through large files (like 1GB+ videos) using minimal RAM footprint.

---

## 🚀 Getting Started

### Prerequisites

Make sure you have Python 3.8+ installed on your machine.

### Installation

1. Clone the repository to your local machine:
   ```bash
   git clone [https://github.com/YOUR_USERNAME/ile-cipher.git](https://github.com/YOUR_USERNAME/file-cipher.git)
   cd file-cipher

2. Install the required dependencies:
    ```bash
    pip install customtkinter cryptography

3. Run the application:
    ```bash
    python main.py

### 📦 Compiling to a Standalone Executable (.exe)

1. Install PyInstaller:
    ```bash
    pip install pyinstaller

2. Build the distribution file (the --collect-all flag is required to grab CustomTkinter's UI assets):
    ```bash
    pyinstaller --noconsole --onefile --collect-all customtkinter app.py

3. Navigate to the newly generated dist/ directory to find your standalone app.exe.

### 🤝 Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the issues page if you want to submit updates or optimizations.

### ✒️ Author
Developed with 💻 by mahmoud