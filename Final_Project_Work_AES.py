 Marshall Calvin StudentID : 221ADM071


# Github link https://github.com/calvinwings/AES_RTU

import tkinter as tk
from Crypto.Cipher import AES
import base64

class AESApp:
    def __init__(self, master):
        self.master = master
        master.title("AES Encryption/Decryption")

        # Create label for input text box
        self.label_input = tk.Label(master, text="Enter message to encrypt/decrypt:")
        self.label_input.pack()

        # Create input text box
        self.input_box = tk.Entry(master)
        self.input_box.pack()

        # Create label for output text box
        self.label_output = tk.Label(master, text="Result:")
        self.label_output.pack()

        # Create output text box
        self.output_box = tk.Entry(master, state="readonly")
        self.output_box.pack()

        # Create Encrypt button
        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack()

        # Create Decrypt button
        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack()

    def encrypt(self):
        # Get input message from text box
        message = self.input_box.get()

        # Pad message with spaces so it is a multiple of 16 bytes
        padded_message = message + " " * (16 - len(message) % 16)

        # Convert key and IV to bytes
        key = b'mysecretpassword'
        iv = b'mysecretpassword'

        # Create AES cipher object and encrypt message
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_message = cipher.encrypt(padded_message.encode('utf-8'))

        # Encode encrypted message in base64
        encoded_message = base64.b64encode(encrypted_message)

        # Display encrypted message in output text box
        self.output_box.config(state="normal")
        self.output_box.delete(0, tk.END)
        self.output_box.insert(0, encoded_message.decode('utf-8'))
        self.output_box.config(state="readonly")

    def decrypt(self):
        # Get input message from text box
        encoded_message = self.input_box.get()

        # Decode encoded message from base64
        encrypted_message = base64.b64decode(encoded_message)

        # Convert key and IV to bytes
        key = b'mysecretpassword'
        iv = b'mysecretpassword'

        # Create AES cipher object and decrypt message
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_message = cipher.decrypt(encrypted_message).rstrip()

        # Display decrypted message in output text box
        self.output_box.config(state="normal")
        self.output_box.delete(0, tk.END)
        self.output_box.insert(0, decrypted_message.decode('utf-8'))
        self.output_box.config(state="readonly")


root = tk.Tk()
my_app = AESApp(root)
root.mainloop()

