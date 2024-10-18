import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.fernet import Fernet
import base64
import os

class EncryptionApp:
    def __init__(self, master):
        self.master = master
        self.master.title("File Encryption/Decryption")
        self.master.geometry("300x150")

        self.encrypt_button = tk.Button(master, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = tk.Button(master, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_button.pack(pady=10)

    def get_key(self, password):
        password = password.encode()  # Convert to bytes
        return base64.urlsafe_b64encode(password.ljust(32)[:32])

    def encrypt_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        password = simpledialog.askstring("Password", "Enter encryption password:", show='*')
        if not password:
            return

        key = self.get_key(password)
        fernet = Fernet(key)

        with open(file_path, 'rb') as file:
            original = file.read()

        encrypted = fernet.encrypt(original)

        with open(file_path + '.encrypted', 'wb') as encrypted_file:
            encrypted_file.write(encrypted)

        messagebox.showinfo("Success", "File encrypted successfully!")

    def decrypt_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.encrypted")])
        if not file_path:
            return

        password = simpledialog.askstring("Password", "Enter decryption password:", show='*')
        if not password:
            return

        key = self.get_key(password)
        fernet = Fernet(key)

        try:
            with open(file_path, 'rb') as enc_file:
                encrypted = enc_file.read()

            decrypted = fernet.decrypt(encrypted)

            with open(file_path[:-10], 'wb') as dec_file:
                dec_file.write(decrypted)

            messagebox.showinfo("Success", "File decrypted successfully!")
        except:
            messagebox.showerror("Error", "Decryption failed. Incorrect password or corrupted file.")

root = tk.Tk()
app = EncryptionApp(root)
root.mainloop()