import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import threading
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64
from PIL import Image, ImageTk
import io

class GradientFrame(tk.Canvas):
    """A gradient frame which uses a canvas to draw the background"""
    def __init__(self, parent, color1="#3a7bd5", color2="#3a6073", **kwargs):
        tk.Canvas.__init__(self, parent, **kwargs)
        self._color1 = color1
        self._color2 = color2
        self.bind("<Configure>", self._draw_gradient)

    def _draw_gradient(self, event=None):
        self.delete("gradient")
        width = self.winfo_width()
        height = self.winfo_height()
        limit = width
        (r1, g1, b1) = self.winfo_rgb(self._color1)
        (r2, g2, b2) = self.winfo_rgb(self._color2)
        r_ratio = float(r2-r1) / limit
        g_ratio = float(g2-g1) / limit
        b_ratio = float(b2-b1) / limit

        for i in range(limit):
            nr = int(r1 + (r_ratio * i))
            ng = int(g1 + (g_ratio * i))
            nb = int(b1 + (b_ratio * i))
            color = "#%4.4x%4.4x%4.4x" % (nr, ng, nb)
            self.create_line(i, 0, i, height, tags=("gradient",), fill=color)
        self.lower("gradient")

class CircularProgressbar(tk.Canvas):
    def __init__(self, parent, width=120, height=120, progress=0, **kwargs):
        super().__init__(parent, width=width, height=height, **kwargs)
        self.width = width
        self.height = height
        self.progress = progress
        self.config(bg='#1a1a2e', highlightthickness=0)
        self.draw_progressbar()

    def draw_progressbar(self):
        self.delete("all")
        # Draw background circle
        self.create_oval(10, 10, self.width-10, self.height-10, 
                         outline="#0f3460", width=4, fill="#1a1a2e")
        
        if self.progress > 0:
            # Draw progress arc
            angle = int(360 * (self.progress / 100))
            self.create_arc(10, 10, self.width-10, self.height-10, 
                            start=90, extent=-angle, outline="#16213e", 
                            width=4, style=tk.ARC)
        
        # Draw text
        self.create_text(self.width/2, self.height/2, 
                         text=f"{int(self.progress)}%", fill="#e94560", 
                         font=('Helvetica', 20, 'bold'))

    def set_progress(self, progress):
        self.progress = progress
        self.draw_progressbar()

class RSAApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Encryptor")
        self.root.geometry("900x600")
        self.root.minsize(900, 600)
        
        # Set theme colors
        self.bg_color = "#1a1a2e"
        self.accent_color = "#e94560"
        self.text_color = "#ffffff"
        self.secondary_color = "#0f3460"
        
        # Initialize variables
        self.public_key = None
        self.private_key = None
        self.selected_file = None
        self.output_dir = None
        self.progress_var = 0
        self.processing = False

        # Set app style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure styles
        self.configure_styles()
        
        # Create main frame with gradient
        self.main_frame = GradientFrame(root, color1="#0f0c29", color2="#24243e", highlightthickness=0)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create content
        self.create_header()
        self.create_tab_control()
        self.create_status_bar()

    def configure_styles(self):
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TButton', 
                             background=self.accent_color, 
                             foreground=self.text_color, 
                             font=('Helvetica', 10, 'bold'),
                             borderwidth=0,
                             padding=10)
        self.style.map('TButton', 
                       background=[('active', '#f25278')])
        
        self.style.configure('TLabel', 
                             background=self.bg_color, 
                             foreground=self.text_color, 
                             font=('Helvetica', 11))
        
        self.style.configure('Header.TLabel', 
                             font=('Helvetica', 24, 'bold'), 
                             foreground=self.text_color)
        
        self.style.configure('Subheader.TLabel', 
                             font=('Helvetica', 14), 
                             foreground=self.text_color)
        
        self.style.configure('TNotebook', 
                             background=self.bg_color, 
                             tabmargins=[2, 5, 2, 0])
        
        self.style.configure('TNotebook.Tab', 
                             background=self.secondary_color,
                             foreground=self.text_color,
                             padding=[20, 10],
                             font=('Helvetica', 10, 'bold'))
        
        self.style.map('TNotebook.Tab', 
                       background=[('selected', self.accent_color)],
                       foreground=[('selected', self.text_color)])
        
        self.style.configure('TSeparator', 
                             background=self.accent_color)

    def create_header(self):
        # Create frame for header
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill=tk.X, padx=20, pady=20)
        
        # Logo and Title
        ttk.Label(header_frame, 
                  text="🔒 Secure File Encryptor", 
                  style='Header.TLabel').pack(side=tk.LEFT)
        
        # Key status indicator
        self.key_status = ttk.Label(header_frame, 
                                    text="No keys loaded", 
                                    style='Subheader.TLabel')
        self.key_status.pack(side=tk.RIGHT, padx=10)

    def create_tab_control(self):
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Create tabs
        self.keys_tab = ttk.Frame(self.notebook)
        self.encrypt_tab = ttk.Frame(self.notebook)
        self.decrypt_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.keys_tab, text="Key Management")
        self.notebook.add(self.encrypt_tab, text="Encrypt Files")
        self.notebook.add(self.decrypt_tab, text="Decrypt Files")
        
        # Fill tabs
        self.create_keys_tab()
        self.create_encrypt_tab()
        self.create_decrypt_tab()

    def create_keys_tab(self):
        # Content frame with some padding
        content = ttk.Frame(self.keys_tab)
        content.pack(fill=tk.BOTH, expand=True, padx=40, pady=20)
        
        # Title
        ttk.Label(content, text="RSA Key Management", 
                 style='Subheader.TLabel').pack(pady=(0, 20))
        
        # Key size section
        key_frame = ttk.Frame(content)
        key_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(key_frame, text="Key Size:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        
        self.key_size_var = tk.StringVar(value="2048")
        key_size_combo = ttk.Combobox(key_frame, textvariable=self.key_size_var, 
                                      values=["1024", "2048", "4096"], width=10, state="readonly")
        key_size_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(key_frame, text="bits (larger keys = more secure, but slower)").grid(
            row=0, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Generate keys button
        generate_btn = ttk.Button(content, text="Generate New Key Pair", 
                                 command=self.generate_keys)
        generate_btn.pack(pady=15)
        
        # Separator
        ttk.Separator(content, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=20)
        
        # Key management section
        key_mgmt_frame = ttk.Frame(content)
        key_mgmt_frame.pack(fill=tk.X, pady=10)
        
        # Create two columns
        left_frame = ttk.Frame(key_mgmt_frame)
        left_frame.grid(row=0, column=0, padx=10, sticky=tk.N)
        
        right_frame = ttk.Frame(key_mgmt_frame)
        right_frame.grid(row=0, column=1, padx=10, sticky=tk.N)
        
        # Export keys section (left)
        ttk.Label(left_frame, text="Export Keys", 
                 style='Subheader.TLabel').pack(anchor=tk.W, pady=(0, 10))
        
        export_public_btn = ttk.Button(left_frame, text="Export Public Key", 
                                      command=self.export_public_key)
        export_public_btn.pack(fill=tk.X, pady=5)
        
        export_private_btn = ttk.Button(left_frame, text="Export Private Key", 
                                       command=self.export_private_key)
        export_private_btn.pack(fill=tk.X, pady=5)
        
        # Import keys section (right)
        ttk.Label(right_frame, text="Import Keys", 
                 style='Subheader.TLabel').pack(anchor=tk.W, pady=(0, 10))
        
        import_public_btn = ttk.Button(right_frame, text="Import Public Key", 
                                      command=self.import_public_key)
        import_public_btn.pack(fill=tk.X, pady=5)
        
        import_private_btn = ttk.Button(right_frame, text="Import Private Key", 
                                       command=self.import_private_key)
        import_private_btn.pack(fill=tk.X, pady=5)

    def create_encrypt_tab(self):
        # Content frame
        content = ttk.Frame(self.encrypt_tab)
        content.pack(fill=tk.BOTH, expand=True, padx=40, pady=20)
        
        # Title 
        ttk.Label(content, text="Encrypt Files", 
                 style='Subheader.TLabel').pack(pady=(0, 20))
        
        # File selection
        file_frame = ttk.Frame(content)
        file_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(file_frame, text="Select File to Encrypt:").grid(
            row=0, column=0, sticky=tk.W, padx=5, pady=5)
        
        self.encrypt_file_var = tk.StringVar()
        file_entry = ttk.Entry(file_frame, textvariable=self.encrypt_file_var, width=50)
        file_entry.grid(row=0, column=1, padx=5, pady=5)
        
        browse_btn = ttk.Button(file_frame, text="Browse", 
                               command=lambda: self.browse_file(self.encrypt_file_var))
        browse_btn.grid(row=0, column=2, padx=5, pady=5)
        
        # Output directory
        out_frame = ttk.Frame(content)
        out_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(out_frame, text="Output Directory:").grid(
            row=0, column=0, sticky=tk.W, padx=5, pady=5)
        
        self.encrypt_out_var = tk.StringVar()
        out_entry = ttk.Entry(out_frame, textvariable=self.encrypt_out_var, width=50)
        out_entry.grid(row=0, column=1, padx=5, pady=5)
        
        browse_out_btn = ttk.Button(out_frame, text="Browse", 
                                   command=lambda: self.browse_directory(self.encrypt_out_var))
        browse_out_btn.grid(row=0, column=2, padx=5, pady=5)
        
        # Progress frame
        progress_frame = ttk.Frame(content)
        progress_frame.pack(fill=tk.X, pady=20)
        
        # Circular progress bar
        self.encrypt_progress = CircularProgressbar(progress_frame)
        self.encrypt_progress.pack(pady=10)
        
        # Encrypt button
        encrypt_btn = ttk.Button(content, text="Encrypt File", 
                                command=lambda: self.process_file(True))
        encrypt_btn.pack(pady=15)

    def create_decrypt_tab(self):
        # Content frame
        content = ttk.Frame(self.decrypt_tab)
        content.pack(fill=tk.BOTH, expand=True, padx=40, pady=20)
        
        # Title 
        ttk.Label(content, text="Decrypt Files", 
                 style='Subheader.TLabel').pack(pady=(0, 20))
        
        # File selection
        file_frame = ttk.Frame(content)
        file_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(file_frame, text="Select File to Decrypt:").grid(
            row=0, column=0, sticky=tk.W, padx=5, pady=5)
        
        self.decrypt_file_var = tk.StringVar()
        file_entry = ttk.Entry(file_frame, textvariable=self.decrypt_file_var, width=50)
        file_entry.grid(row=0, column=1, padx=5, pady=5)
        
        browse_btn = ttk.Button(file_frame, text="Browse", 
                               command=lambda: self.browse_file(self.decrypt_file_var))
        browse_btn.grid(row=0, column=2, padx=5, pady=5)
        
        # Output directory
        out_frame = ttk.Frame(content)
        out_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(out_frame, text="Output Directory:").grid(
            row=0, column=0, sticky=tk.W, padx=5, pady=5)
        
        self.decrypt_out_var = tk.StringVar()
        out_entry = ttk.Entry(out_frame, textvariable=self.decrypt_out_var, width=50)
        out_entry.grid(row=0, column=1, padx=5, pady=5)
        
        browse_out_btn = ttk.Button(out_frame, text="Browse", 
                                   command=lambda: self.browse_directory(self.decrypt_out_var))
        browse_out_btn.grid(row=0, column=2, padx=5, pady=5)
        
        # Progress frame
        progress_frame = ttk.Frame(content)
        progress_frame.pack(fill=tk.X, pady=20)
        
        # Circular progress bar
        self.decrypt_progress = CircularProgressbar(progress_frame)
        self.decrypt_progress.pack(pady=10)
        
        # Decrypt button
        decrypt_btn = ttk.Button(content, text="Decrypt File", 
                                command=lambda: self.process_file(False))
        decrypt_btn.pack(pady=15)

    def create_status_bar(self):
        # Create a status bar at the bottom
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, 
                              relief=tk.SUNKEN, anchor=tk.W, padding=(10, 2))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def generate_keys(self):
        # Generate new RSA key pair
        try:
            key_size = int(self.key_size_var.get())
            
            self.status_var.set(f"Generating {key_size}-bit RSA key pair...")
            self.root.update_idletasks()
            
            # Generate keys in a separate thread to avoid UI freezing
            threading.Thread(target=self._generate_keys_thread, args=(key_size,)).start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate keys: {str(e)}")
            self.status_var.set("Error generating keys")

    def _generate_keys_thread(self, key_size):
        try:
            # Generate private key
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            
            # Extract public key
            self.public_key = self.private_key.public_key()
            
            # Update UI
            self.root.after(0, self._update_key_status)
            self.root.after(0, lambda: self.status_var.set(f"{key_size}-bit RSA key pair generated successfully"))
            self.root.after(0, lambda: messagebox.showinfo("Success", "New RSA key pair generated successfully"))
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to generate keys: {str(e)}"))
            self.root.after(0, lambda: self.status_var.set("Error generating keys"))

    def _update_key_status(self):
        if self.public_key and self.private_key:
            self.key_status.config(text="Keys loaded ✓")
        elif self.public_key:
            self.key_status.config(text="Public key loaded")
        elif self.private_key:
            self.key_status.config(text="Private key loaded")
        else:
            self.key_status.config(text="No keys loaded")

    def export_public_key(self):
        if not self.public_key:
            messagebox.showerror("Error", "No public key available")
            return
            
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".pem",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
                title="Save Public Key"
            )
            
            if not filename:
                return
                
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            with open(filename, 'wb') as f:
                f.write(public_pem)
                
            self.status_var.set(f"Public key exported to {filename}")
            messagebox.showinfo("Success", "Public key exported successfully")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export public key: {str(e)}")
            self.status_var.set("Error exporting public key")

    def export_private_key(self):
        if not self.private_key:
            messagebox.showerror("Error", "No private key available")
            return
            
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".pem",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
                title="Save Private Key"
            )
            
            if not filename:
                return
                
            # Ask for password
            password = self.prompt_for_password("Enter password to encrypt private key:")
            
            if password is None:  # User cancelled
                return
                
            # Serialize private key with password encryption
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
                if password else serialization.NoEncryption()
            )
            
            with open(filename, 'wb') as f:
                f.write(private_pem)
                
            self.status_var.set(f"Private key exported to {filename}")
            messagebox.showinfo("Success", "Private key exported successfully")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export private key: {str(e)}")
            self.status_var.set("Error exporting private key")

    def import_public_key(self):
        try:
            filename = filedialog.askopenfilename(
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
                title="Open Public Key"
            )
            
            if not filename:
                return
                
            with open(filename, 'rb') as f:
                public_pem = f.read()
                
            self.public_key = serialization.load_pem_public_key(
                public_pem,
                backend=default_backend()
            )
            
            self._update_key_status()
            self.status_var.set(f"Public key imported from {filename}")
            messagebox.showinfo("Success", "Public key imported successfully")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import public key: {str(e)}")
            self.status_var.set("Error importing public key")

    def import_private_key(self):
        try:
            filename = filedialog.askopenfilename(
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
                title="Open Private Key"
            )
            
            if not filename:
                return
            
            with open(filename, 'rb') as f:
                private_pem = f.read()
            
            # Check if key is encrypted
            if b"ENCRYPTED" in private_pem:
                password = self.prompt_for_password("Enter password for private key:")
                if password is None:  # User cancelled
                    return
                    
                self.private_key = serialization.load_pem_private_key(
                    private_pem,
                    password=password.encode() if password else None,
                    backend=default_backend()
                )
            else:
                self.private_key = serialization.load_pem_private_key(
                    private_pem,
                    password=None,
                    backend=default_backend()
                )
            
            # Extract public key from private key
            self.public_key = self.private_key.public_key()
            
            self._update_key_status()
            self.status_var.set(f"Private key imported from {filename}")
            messagebox.showinfo("Success", "Private key imported successfully")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import private key: {str(e)}")
            self.status_var.set("Error importing private key")

    def prompt_for_password(self, prompt):
        # Create a custom dialog to get password
        dialog = tk.Toplevel(self.root)
        dialog.title("Password Required")
        dialog.geometry("400x180")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Set dialog style
        dialog.configure(bg=self.bg_color)
        
        # Center the dialog
        x = self.root.winfo_x() + (self.root.winfo_width() - 400) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - 180) // 2
        dialog.geometry(f"+{x}+{y}")
        
        # Create a frame with gradient background
        frame = GradientFrame(dialog, color1="#0f0c29", color2="#24243e")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Add components
        ttk.Label(frame, text=prompt, style='Subheader.TLabel').pack(pady=(20, 10))
        
        password_var = tk.StringVar()
        password_entry = ttk.Entry(frame, textvariable=password_var, show="•", width=30)
        password_entry.pack(pady=10)
        
        # Store the result
        result = [None]
        
        def on_ok():
            result[0] = password_var.get()
            dialog.destroy()
            
        def on_cancel():
            dialog.destroy()
        
        # Buttons frame
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=20)
        
        ok_button = ttk.Button(button_frame, text="OK", command=on_ok)
        ok_button.pack(side=tk.LEFT, padx=10)
        
        cancel_button = ttk.Button(button_frame, text="Cancel", command=on_cancel)
        cancel_button.pack(side=tk.LEFT, padx=10)
        
        # Set focus to password entry
        password_entry.focus_set()
        
        # Bind enter key to OK button
        dialog.bind("<Return>", lambda event: on_ok())
        
        # Wait for dialog to close
        self.root.wait_window(dialog)
        
        return result[0]

    def browse_file(self, var):
        filename = filedialog.askopenfilename(title="Select File")
        if filename:
            var.set(filename)

    def browse_directory(self, var):
        directory = filedialog.askdirectory(title="Select Directory")
        if directory:
            var.set(directory)

    def process_file(self, encrypt=True):
        if encrypt and not self.public_key:
            messagebox.showerror("Error", "Public key is required for encryption")
            return
            
        if not encrypt and not self.private_key:
            messagebox.showerror("Error", "Private key is required for decryption")
            return
            
        # Get file path and output directory
        file_var = self.encrypt_file_var if encrypt else self.decrypt_file_var
        out_var = self.encrypt_out_var if encrypt else self.decrypt_out_var
        progress_widget = self.encrypt_progress if encrypt else self.decrypt_progress
        
        file_path = file_var.get().strip()
        output_dir = out_var.get().strip()
        
        if not file_path:
            messagebox.showerror("Error", "Please select a file")
            return
            
        if not os.path.isfile(file_path):
            messagebox.showerror("Error", "Selected file does not exist")
            return
            
        if not output_dir:
            messagebox.showerror("Error", "Please select an output directory")
            return
            
        if not os.path.isdir(output_dir):
            messagebox.showerror("Error", "Selected output directory does not exist")
            return
            
        # Determine output filename
        file_name = os.path.basename(file_path)
        if encrypt:
            output_path = os.path.join(output_dir, f"{file_name}.enc")
        else:
            if file_name.endswith('.enc'):
                output_path = os.path.join(output_dir, file_name[:-4])
            else:
                output_path = os.path.join(output_dir, f"decrypted_{file_name}")
                
        # Confirm overwrite if file exists
        if os.path.exists(output_path):
            if not messagebox.askyesno("Confirm Overwrite", 
                                      f"The file {output_path} already exists. Overwrite?"):
                return
                
        # Start processing in a separate thread
        if not self.processing:
            self.processing = True
            self.status_var.set(f"{'Encrypting' if encrypt else 'Decrypting'} file...")
            
            threading.Thread(target=self._process_file_thread, 
                            args=(file_path, output_path, encrypt, progress_widget)).start()

    def _process_file_thread(self, input_path, output_path, encrypt, progress_widget):
        try:
            # Get file size for progress reporting
            file_size = os.path.getsize(input_path)
            chunk_size = 32  # For encryption
            if not encrypt:
                chunk_size = 256  # For decryption (depends on key size)
                
            # Setup progress reporting
            processed_size = 0
            
            with open(input_path, 'rb') as in_file, open(output_path, 'wb') as out_file:
                if encrypt:
                    # For encryption, we process the file in chunks
                    # First, write the header with version info
                    out_file.write(b"RSAv1\n")
                    
                    while True:
                        chunk = in_file.read(chunk_size)
                        if not chunk:
                            break
                            
                        # Encrypt the chunk
                        encrypted = self.public_key.encrypt(
                            chunk,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        
                        # Write the length of encrypted chunk followed by the chunk
                        out_file.write(len(encrypted).to_bytes(4, byteorder='big'))
                        out_file.write(encrypted)
                        
                        # Update progress
                        processed_size += len(chunk)
                        progress = min(100, int(processed_size * 100 / file_size))
                        self.root.after()
