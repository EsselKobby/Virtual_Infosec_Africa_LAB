# Initial Setup and Imports

# Internal Modules
import os
import sys
import time
import string
import io
import logging
import requests
import threading
from itertools import product
from concurrent.futures import ThreadPoolExecutor, as_completed

# Installed External Modules
import msoffcrypto
import pyzipper
import PyPDF2
import colorama
from tqdm import tqdm
from tabulate import tabulate
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
from PIL import Image, ImageTk

# Colorama initialization for colored console output
colorama.init()

# Logging Configuration Setup
logging.basicConfig(filename='password_cracker.log', level=logging.INFO, format='%(asctime)s -%(levelname)s -%(message)s')

# Global Variable Definition
stop_flag = False #Global flag for the attack stoppage/halt
results = []  # Global results list

# Utility Functions



# Fetch Function to get path to bundled resources in PyInstaller
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# Funtion Trial on different file types
def try_password(file_path, file_type, password):
    logging.info(f"Trying password: {password}")
    try:
        if file_type in ['xls', 'xlsx', 'doc', 'docx']:
            return try_office_password(file_path, password)
        elif file_type == 'zip':
            return try_zip_password(file_path, password)
        elif file_type == 'pdf':
            return try_pdf_password(file_path, password)
        else:
            logging.error(f"Unsupported password file type.")
            return False
    except Exception as e:
        logging.error(f"Error trying password {password} | {e}")
        return False

    
# MS Office password function definition
def try_office_password(file_path, password):
    # Open file and File Decryption using msoffcrypto
    with open(file_path, "rb") as f:
        file = msoffcrypto.OfficeFile(f)
        file.load_key(password=password)
        with io.BytesIO() as decrypted:
            file.decrypt(decrypted)
            return True


# ZIP files password function definition
def try_zip_password(file_path, password):
    # Open the ZIP file and attempt using PyZipper
    with pyzipper.AESZipFile(file_path) as zf:
        zf.extractall(pwd=password.encode('utf-8'))
        return True


# PDF files password definition
def try_pdf_password(file_path, password):
    #Opening up of PDF and Decryption using PyPDF2
    reader = PyPDF2.PdfReader(file_path)
    if reader.is_encrypted:
        reader.decrypt(password)
        reader.pages[0]
        return False

# Multithreaded password attempts function
def attempt_passwords(file_path, file_type, passwords, results, batch_index):
    for password in passwords:
        if try_password(file_path, file_type, password):
            results[batch_index] = (password, "Success")
            return password
        else:
            results[batch_index] = (password, "Unsuccessful")
        return None


# File Type Based on File Extension Function

def get_file_type(file_path):
    extension = os.path.splitext(file_path)[1].lower()
    if extension in ['xls', 'xlsx']:
        return 'xls'
    elif extension in ['.doc', '.docx']:
        return 'doc'
    elif extension == '.zip':
        return 'pdf'
    else:
        return None


# File Reading with Fallback Encoding and Error hand
def read_file_lines(file_path):
    encodings = ['utf-8', 'latin-1', 'ascii']
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                return[line.strip() for line in f.readlines()]
        except UnicodeDecodeError:
            continue
    raise ValueError(f"failed to decode file {file_path} with files encodings")

# Progress message update function
def update_progress(message):
    progress_var.set(message)

# Main log function update
def update_log(message):
    output_log.insert(tk.END, message + "\n")
    output_log.see(tk.END)

def update_results_log(message, success=False):
    if success:
        results_log.tag_configure("success", foreground="green")
        results_log.insert(tk.END, message + "\n", "success")
    else:
        results.log.insert(tk.END, message + "\n")
    results_log.see(tk.END)

# Progress bar and ETA label update function
def update_progress_bar(current, total, start_time)