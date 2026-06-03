import os
import re
import sys
import zlib
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

SALT_SIZE = 16
BLOCK_SIZE = 16
CHUNK_SIZE = 64 * 1024 

def is_strong_password(password: str) -> bool:
    if len(password) < 8: return False
    if not re.search(r"[A-Z]", password): return False
    if not re.search(r"[a-z]", password): return False
    if not re.search(r"\d", password): return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\\/~`';]", password): return False
    return True

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=100_000
    )
    return kdf.derive(password.encode())

# ---- Background Worker Logic ----
def file_worker(file_path, password, encrypt=True):
    try:
        total_size = os.path.getsize(file_path)
        bytes_processed = 0

        encrypt_btn.configure(state="disabled")
        decrypt_btn.configure(state="disabled")
        root.after(0, update_progress, 0)

        if encrypt:
            base_path, ext = os.path.splitext(file_path)
            out_path = f"{base_path}_enc{ext}.enc"
            
            salt = os.urandom(SALT_SIZE)
            iv = os.urandom(BLOCK_SIZE)
            key = derive_key(password, salt)
            
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
            encryptor = cipher.encryptor()
            compressor = zlib.compressobj(level=6)

            with open(file_path, "rb") as f_in, open(out_path, "wb") as f_out:
                f_out.write(salt + iv)
                while True:
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk: break
                    comp_chunk = compressor.compress(chunk)
                    if comp_chunk:
                        f_out.write(encryptor.update(comp_chunk))
                    bytes_processed += len(chunk)
                    root.after(0, update_progress, (bytes_processed / total_size))

                comp_chunk = compressor.flush()
                if comp_chunk:
                    f_out.write(encryptor.update(comp_chunk))
                f_out.write(encryptor.finalize())
                
            root.after(0, lambda: messagebox.showinfo("Success", f"Encrypted successfully!\nSaved as: {out_path}"))
            
        else:
            if not file_path.endswith(".enc"):
                if not messagebox.askyesno("Warning", "File lacks .enc extension. Continue?"):
                    reset_ui()
                    return
                
            clean_path = file_path[:-4] if file_path.endswith(".enc") else file_path
            base_path, ext = os.path.splitext(clean_path)

            if base_path.endswith("_enc"):
                base_path = base_path[:-4]
                
            out_path = f"{base_path}_dec{ext}"
            
            with open(file_path, "rb") as f_in:
                salt = f_in.read(SALT_SIZE)
                iv = f_in.read(BLOCK_SIZE)
                bytes_processed += (SALT_SIZE + BLOCK_SIZE)
                
                key = derive_key(password, salt)
                cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
                decryptor = cipher.decryptor()
                decompressor = zlib.decompressobj()

                with open(out_path, "wb") as f_out:
                    while True:
                        chunk = f_in.read(CHUNK_SIZE)
                        if not chunk: break
                        dec_chunk = decryptor.update(chunk)
                        if dec_chunk:
                            try:
                                f_out.write(decompressor.decompress(dec_chunk))
                            except zlib.error:
                                raise Exception("Password incorrect or file corrupted.")
                        bytes_processed += len(chunk)
                        root.after(0, update_progress, (bytes_processed / total_size))

                    dec_chunk = decryptor.finalize()
                    if dec_chunk:
                        f_out.write(decompressor.decompress(dec_chunk))
                    try:
                        f_out.write(decompressor.flush())
                    except zlib.error:
                        raise Exception("Password incorrect or file corrupted.")
                        
            root.after(0, lambda: messagebox.showinfo("Success", f"Decrypted successfully!\nSaved as: {out_path}"))

    except Exception as e:
        root.after(0, lambda: messagebox.showerror("Error", f"An error occurred: {str(e)}"))
    finally:
        root.after(0, reset_ui)

# ---- UI Triggers ----
def start_processing(encrypt=True):
    file_path = file_entry.get()
    password = password_entry.get()
    if not file_path or not password:
        messagebox.showerror("Error", "Please select a file and enter a password.")
        return
    if not is_strong_password(password):
        messagebox.showerror("Weak Password", "Password must be at least 8 chars long and contain uppercase, lowercase, numbers, and symbols.")
        return

    threading.Thread(target=file_worker, args=(file_path, password, encrypt), daemon=True).start()

def update_progress(value):
    progress_bar.set(value)
    percent_label.configure(text=f"{value*100:.1f}%")

def reset_ui():
    encrypt_btn.configure(state="normal")
    decrypt_btn.configure(state="normal")
    progress_bar.set(0)
    percent_label.configure(text="0.0%")

def browse_file():
    filename = filedialog.askopenfilename()
    if filename:
        file_entry.delete(0, "end")
        file_entry.insert(0, filename)

def center_window(window, width=500, height=260):
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)
    window.geometry(f"{width}x{height}+{x}+{y}")

def get_asset_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

# ---- GUI Configuration ----
ctk.set_appearance_mode("dark")       
ctk.set_default_color_theme("blue")   

root = ctk.CTk()                      
root.title("File Cipher")
root.resizable(False, False)

center_window(root, 520, 290) 

icon_path = get_asset_path("assets/icon.ico")
root.wm_iconbitmap(icon_path)

import ctypes
try:
    myappid = 'mahmoudev.filecipher.version.1' 
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
except:
    pass

# Main Container Frame
main_frame = ctk.CTkFrame(root, fg_color="transparent")
main_frame.pack(fill="both", expand=True, padx=25, pady=20)

# File Entry Row
file_label = ctk.CTkLabel(main_frame, text="File Path:", font=("Arial", 13, "bold"))
file_label.grid(row=0, column=0, sticky="w", pady=(0, 5))

file_entry = ctk.CTkEntry(main_frame, width=320, placeholder_text="Select a file to process...")
file_entry.grid(row=1, column=0, sticky="we", padx=(0, 10))

browse_btn = ctk.CTkButton(main_frame, text="Browse", width=100, command=browse_file)
browse_btn.grid(row=1, column=1, sticky="e")

# Password Entry Row
pass_label = ctk.CTkLabel(main_frame, text="Secret Key / Password:", font=("Arial", 13, "bold"))
pass_label.grid(row=2, column=0, sticky="w", pady=(15, 5))

password_entry = ctk.CTkEntry(main_frame, show="*", placeholder_text="Enter strong password...")
password_entry.grid(row=3, column=0, columnspan=2, sticky="we")

# Progress Row
progress_bar = ctk.CTkProgressBar(main_frame, width=370)
progress_bar.grid(row=4, column=0, sticky="w", pady=(25, 0))
progress_bar.set(0)

percent_label = ctk.CTkLabel(main_frame, text="0.0%", font=("Arial", 12, "bold"))
percent_label.grid(row=4, column=1, sticky="e", pady=(25, 0))

# Action Buttons Frame
btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
btn_frame.grid(row=5, column=0, columnspan=2, sticky="we", pady=(25, 0))

encrypt_btn = ctk.CTkButton(btn_frame, text="Encrypt File", fg_color="#E74C3C", hover_color="#C0392B", width=140, font=("Arial", 13, "bold"), command=lambda: start_processing(encrypt=True))
encrypt_btn.pack(side="left", padx=(0, 10))

decrypt_btn = ctk.CTkButton(btn_frame, text="Decrypt File", fg_color="#3498DB", hover_color="#2980B9", width=140, font=("Arial", 13, "bold"), command=lambda: start_processing(encrypt=False))
decrypt_btn.pack(side="left")

dev_label = ctk.CTkLabel(main_frame, text="Developed by Mahmoud.", font=("Arial", 12, "italic"), text_color="white")
dev_label.grid(row=5, column=0, columnspan=2, sticky="e", pady=(20, 0), padx=(0, 20))

root.mainloop()