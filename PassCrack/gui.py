# Library Imports
import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
from PIL import Image, ImageTk


#  Main window Initialization
root = tk.Tk()
root.title("FORESS TECH Password Cracker")
root.geometry("800x700")

# Function to get the path to bundled resources (e.g., logo image)
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# Window Icon Setup
logo = Image.open(resource_path("./logo.png"))
logo = logo.resize((64, 64), Image.LANCZOS)
logo = ImageTk.PhotoImage(logo)
root.iconphoto(False, logo)

# Main Frame Setup
main_frame = ttk.Frame(root, padding="10")
main_frame.grid(row=0, column=0, sticky="nsew")

# UI Components styling
style = ttk.Style()
style.configure("TLabel", background="#05050F", foreground="#ff0000")
style.configure("TFrame", background="#05050F")
style.configure("TButton", background="black", foreground="red", bordercolor="#009933", focusthickness=3, focuscolor="none")
style.configure("Green.Horizontal.TProgressbar", troughcolor='#151525', background='#00FF00', bordercolor='#05050F')

# Attack Type DropDown Components
attack_type_var = tk.StringVar(value="brute_force")
attack_type_label = ttk.Label(main_frame, text="Select Attack Type:", font=("Courier New", 12))
attack_type_label.grid(row=0, column=0, pady=5, padx=5, sticky="w")
attack_type_menu = ttk.Combobox(main_frame, textvariable=attack_type_var, state="readonly", font=("Courier New", 12))
attack_type_menu['values'] = ("brute_force", "dictionary", "reverse_brute_force")
attack_type_menu.grid(row=0, column=1, pady=5, padx=(0, 5), sticky="w")

# File Selection Frame Setup
file_type_frame = ttk.Frame(main_frame, style="TFrame")
file_type_label = ttk.Label(file_type_frame, text="Select File Type:", font=("Courier New", 12))
file_type_label.grid(row=0, column=0, pady=5, padx=5, sticky="w")
file_type_var = tk.StringVar(value="zip")
file_type_menu = ttk.Combobox(file_type_frame, textvariable=file_type_var, state="readonly", font=("Courier New", 12))
file_type_menu['values'] = ("zip", "xls", "doc", "pdf")
file_type_menu.grid(row=0, column=1, pady=5, padx=(0, 5), sticky="w")
file_type_frame.grid(row=1, column=0, columnspan=3, pady=5, padx=5, sticky="ew")

# Brute force configuration frame
brute_force_frame = ttk.Frame(main_frame, style="TFrame")
ttk.Label(brute_force_frame, text="File Path:", font=("Courier New", 12)).grid(row=2, column=0, pady=5, padx=5, sticky="w")
file_path_entry = ttk.Entry(brute_force_frame, width=40, font=("Courier New", 12), background="#151525", foreground="red")
file_path_entry.grid(row=2, column=1, pady=5, padx=5, sticky="w")
ttk.Button(brute_force_frame, text="Browse", style="TButton").grid(row=2, column=2, pady=5, padx=5, sticky="w")
ttk.Label(brute_force_frame, text="Max Length:", font=("Courier New", 12)).grid(row=3, column=0, pady=5, padx=5, sticky="w")
max_length_entry = ttk.Entry(brute_force_frame, width=10, font=("Courier New", 12), background="#151525", foreground="red")
max_length_entry.grid(row=3, column=1, pady=5, padx=5, sticky="w")
ttk.Label(brute_force_frame, text="Charset:", font=("Courier New", 12)).grid(row=4, column=0, pady=5, padx=5, sticky="w")
charset_entry = ttk.Entry(brute_force_frame, width=40, font=("Courier New", 12), background="#151525", foreground="red")
charset_entry.grid(row=4, column=1, pady=5, padx=5, sticky="w")

# Dictionary attack configuration frame
dictionary_frame = ttk.Frame(main_frame, style="TFrame")
ttk.Label(dictionary_frame, text="File Path:", font=("Courier New", 12)).grid(row=2, column=0, pady=5, padx=5, sticky="w")
file_path_entry_dict = ttk.Entry(dictionary_frame, width=40, font=("Courier New", 12), background="#151525", foreground="red")
file_path_entry_dict.grid(row=2, column=1, pady=5, padx=5, sticky="w")
ttk.Button(dictionary_frame, text="Browse", style="TButton").grid(row=2, column=2, pady=5, padx=5, sticky="w")
ttk.Label(dictionary_frame, text="Dictionary File:", font=("Courier New", 12)).grid(row=3, column=0, pady=5, padx=5, sticky="w")
dictionary_file_entry = ttk.Entry(dictionary_frame, width=40, font=("Courier New", 12), background="#151525", foreground="red")
dictionary_file_entry.grid(row=3, column=1, pady=5, padx=5, sticky="w")
ttk.Button(dictionary_frame, text="Browse", style="TButton").grid(row=3, column=2, pady=5, padx=5, sticky="w")

# Reverse brute force configuration frame
reverse_brute_force_frame = ttk.Frame(main_frame, style="TFrame")
ttk.Label(reverse_brute_force_frame, text="Target URL:", font=("Courier New", 12)).grid(row=2, column=0, pady=5, padx=5, sticky="w")
url_entry = ttk.Entry(reverse_brute_force_frame, width=40, font=("Courier New", 12), background="#151525", foreground="red")
url_entry.grid(row=2, column=1, pady=5, padx=5, sticky="w")
ttk.Label(reverse_brute_force_frame, text="Usernames File:", font=("Courier New", 12)).grid(row=3, column=0, pady=5, padx=5, sticky="w")
usernames_file_entry = ttk.Entry(reverse_brute_force_frame, width=40, font=("Courier New", 12), background="#151525", foreground="red")
usernames_file_entry.grid(row=3, column=1, pady=5, padx=5, sticky="w")
ttk.Button(reverse_brute_force_frame, text="Browse", style="TButton").grid(row=3, column=2, pady=5, padx=5, sticky="w")
ttk.Label(reverse_brute_force_frame, text="Common Passwords File:", font=("Courier New", 12)).grid(row=4, column=0, pady=5, padx=5, sticky="w")
common_passwords_file_entry = ttk.Entry(reverse_brute_force_frame, width=40, font=("Courier New", 12), background="#151525", foreground="red")
common_passwords_file_entry.grid(row=4, column=1, pady=5, padx=5, sticky="w")
ttk.Button(reverse_brute_force_frame, text="Browse", style="TButton").grid(row=4, column=2, pady=5, padx=5, sticky="w")

# Run, Stop, and Clear buttons
ttk.Button(main_frame, text="Run", style="TButton", width=15).grid(row=5, column=0, pady=10, padx=5, sticky="ew")
ttk.Button(main_frame, text="Stop", style="TButton", width=15).grid(row=5, column=1, pady=10, padx=5, sticky="ew")
ttk.Button(main_frame, text="Clear", style="TButton", width=15).grid(row=5, column=2, pady=10, padx=5, sticky="ew")

# Progress and output display
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

# Column configurations
root.grid_columnconfigure(0, weight=1)
main_frame.grid_columnconfigure(0, weight=1)
main_frame.grid_columnconfigure(1, weight=1)
main_frame.grid_columnconfigure(2, weight=1)
output_frame.grid_columnconfigure(0, weight=1)

# Step 15: Start the main loop
root.mainloop()
