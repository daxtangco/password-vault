import sqlite3
import hashlib
import string
import random
from tkinter import *
from tkinter import simpledialog, Toplevel, END, messagebox, ttk
from functools import partial
import uuid
import pyperclip
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

backend = default_backend()
salt = b'2444'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

encryptionKey = 0

def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)

def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)


# Database code
with sqlite3.connect('password_vault.db') as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL,
recoveryKey TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
platform TEXT NOT NULL,
account TEXT NOT NULL,
password TEXT NOT NULL);
""")

# Initiate window
window = Tk()
window.update()
window.title("Password Vault")

def customPasswordGenerator():
    characters = string.ascii_letters + string.digits + string.punctuation
    length = random.randint(10, 15)
    password = ''.join(random.choice(characters) for i in range(length))
    return password


# Create PopUp
def popUp(text, parent):
    answer = None

    # Create a Toplevel window with 'parent' as the master
    popup_window = Toplevel(parent)
    popup_window.title("Enter Information")

    screen_width = parent.winfo_screenwidth()
    screen_height = parent.winfo_screenheight()

    x = (screen_width - 300) / 2
    y = (screen_height - 150) / 2

    popup_window.geometry(f"300x150+{int(x)}+{int(y)}")

    lbl = Label(popup_window, text=text)
    lbl.pack()

    entry = Entry(popup_window, show="*") if text == "Password" else Entry(popup_window)
    entry.pack()

    def generatePassword():
        generated_password = customPasswordGenerator()
        entry.delete(0, END)
        entry.insert(0, generated_password)

    if text == "Password:":
        btn_generate = Button(popup_window, text="Generate Password", command=generatePassword)
        btn_generate.pack(pady=5)

    def save():
        nonlocal answer
        answer = entry.get()
        popup_window.destroy()

    btn_save = Button(popup_window, text="Save", command=save)
    btn_save.pack(pady=5)

    popup_window.focus_set()
    popup_window.grab_set()
    popup_window.wait_window()

    return answer


# Hash password function
def hashPassword(input):
    hash1 = hashlib.md5(input)
    hash1 = hash1.hexdigest()
    return hash1


# Set up master password screen
def center_window(window):
    window.update_idletasks()
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    width = window.winfo_width()
    height = window.winfo_height()
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    window.geometry(f"+{x}+{y}")

def firstTimeScreen():
    cursor.execute('DELETE FROM vault')
        
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('350x200')
    window.resizable(False, False)
    window.eval('tk::PlaceWindow . center')

    lbl = Label(window, text="Choose a Master Password")
    lbl.pack()

    txt = Entry(window, width=30, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window, text="Re-enter password")
    lbl1.pack()

    txt1 = Entry(window, width=30, show="*")
    txt1.pack()

    def savePassword():
        if txt.get() == txt1.get():
            sql = "DELETE FROM masterpassword WHERE id = 1"

            cursor.execute(sql)

            hashedPassword = hashPassword(txt.get().encode('utf-8'))
            key = str(uuid.uuid4().hex)
            recoveryKey = hashPassword(key.encode('utf-8'))

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))
            
            insert_password = """INSERT INTO masterpassword(password, recoveryKey)
            VALUES(?, ?) """
            cursor.execute(insert_password, ((hashedPassword), (recoveryKey)))
            db.commit()

            recoveryScreen(key)
        else:
            lbl.config(text="Passwords don't match")

    btn = Button(window, text="Save", command=savePassword)
    btn.pack(pady=5)


def resetScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('350x150')
    window.resizable(False, False)
    window.eval('tk::PlaceWindow . center')

    lbl = Label(window, text="Enter Recovery Key")
    lbl.pack()

    txt = Entry(window, width=30)
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.pack()

    def getRecoveryKey():
        recoveryKeyCheck = hashPassword(str(txt.get()).encode('utf-8'))
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1 AND recoveryKey = ?', [(recoveryKeyCheck)])
        return cursor.fetchall()

    def checkRecoveryKey():
        checked = getRecoveryKey()

        if checked:
            firstTimeScreen()
        else:
            txt.delete(0, 'end')
            lbl1.config(text='Wrong Key')

    btn = Button(window, text="Check Key", command=checkRecoveryKey)
    btn.pack(pady=5)

def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('350x200')
    window.resizable(False, False)
    window.eval('tk::PlaceWindow . center')

    lbl = Label(window, text="Save this key to be able to recover account")
    lbl.pack()

    lbl1 = Label(window, text=key)
    lbl1.pack()

    def copyKey():
        key = lbl1['text']
        pyperclip.copy(key)
        messagebox.showinfo("Copied", "Recovery key copied to clipboard!")

    btn_copy = Button(window, text="Copy Key", command=copyKey)
    btn_copy.pack(pady=5)


    def done():
        vaultScreen(window)

    btn_done = Button(window, text="Done", command=done)
    btn_done.pack(pady=5)



def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('350x150')
    window.resizable(False, False)
    window.eval('tk::PlaceWindow . center')

    lbl = Label(window, text="Enter Master Password")
    lbl.pack()

    txt = Entry(window, width=30, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.pack()

    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1 AND password = ?', [(checkHashedPassword)])
        return cursor.fetchall()

    def checkPassword():
        password = getMasterPassword()

        if password:
            vaultScreen(window)
        else:
            txt.delete(0, 'end')
            lbl1.config(text="Wrong Password")

    def resetPassword():
        resetScreen()

    btn = Button(window, text="Submit", command=checkPassword)
    btn.pack(pady=5)

    btn = Button(window, text="Reset Password", command=resetPassword)
    btn.pack(pady=5)


def vaultScreen(window):
    window.geometry("800x500")

    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()

    x = (screen_width - 800) / 2
    y = (screen_height - 500) / 2

    window.geometry(f"800x500+{int(x)}+{int(y)}")

    for widget in window.winfo_children():
        widget.destroy()

    main_frame = Frame(window)
    main_frame.pack(fill=BOTH, expand=1)

    my_canvas = Canvas(main_frame)
    my_canvas.pack(side=LEFT, fill=BOTH, expand=1)

    my_scrollbar = ttk.Scrollbar(main_frame, orient=VERTICAL, command=my_canvas.yview)
    my_scrollbar.pack(side=RIGHT, fill=Y)

    my_canvas.configure(yscrollcommand=my_scrollbar.set)
    my_canvas.bind('<Configure>', lambda e: my_canvas.configure(scrollregion=my_canvas.bbox("all")))

    second_frame = Frame(my_canvas)

    my_canvas.create_window((0, 0), window=second_frame, anchor="nw")


    btn_store_new = Button(second_frame, text="Add Account", command=addEntry)
    btn_store_new.grid(row=1, column=1, pady=10, columnspan=5)  # Centered button

    lbl_platform = Label(second_frame, text="Platform")
    lbl_platform.grid(row=2, column=0, padx=40)
    lbl_account = Label(second_frame, text="Account")
    lbl_account.grid(row=2, column=1, padx=40)
    lbl_password = Label(second_frame, text="Password")
    lbl_password.grid(row=2, column=2, padx=40)

    cursor.execute("SELECT * FROM vault")
    vault_data = cursor.fetchall()

    for i, data in enumerate(vault_data, start=3):
        lbl_platform = Label(second_frame, text=data[1])
        lbl_platform.grid(column=0, row=i)

        lbl_account = Label(second_frame, text=data[2])
        lbl_account.grid(column=1, row=i)

        password_text = "*" * len(data[3])  # Display asterisks for each character of the password
        lbl_password = Label(second_frame, text=password_text)
        lbl_password.grid(column=2, row=i)

        btn_copy_acc = Button(second_frame, text="Copy Acc", command=lambda: copyAcc(window, data[2]))
        btn_copy_acc.grid(column=3, row=i, pady=10)

        btn_copy_pass = Button(second_frame, text="Copy Pass", command=lambda: copyPass(window, data[3]))
        btn_copy_pass.grid(column=4, row=i, pady=10)

        btn_update = Button(second_frame, text="Update", command=partial(updateEntry, data[0]))
        btn_update.grid(column=5, row=i, pady=10)

        btn_delete = Button(second_frame, text="Delete", command=partial(removeEntry, data[0]))
        btn_delete.grid(column=6, row=i, pady=10)


def addEntry():
    platform = popUp("Platform:", window)
    if platform is None:
        return

    account = popUp("Account:", window)
    if account is None:
        return

    password = popUp("Password:", window)
    if password is None:
        return

    insert_fields = """INSERT INTO vault(platform, account, password)
    VALUES(?, ?, ?)"""

    cursor.execute(insert_fields, (platform, account, password))
    db.commit()
    vaultScreen(window)

def updateEntry(input):
    update = "Type new password"
    password = popUp("Password:")

    cursor.execute("UPDATE vault SET password = ? WHERE id = ?", (password, input,))
    db.commit()
    vaultScreen(window)

def removeEntry(input):
    cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
    db.commit()
    vaultScreen(window)

def copyAcc(window, input):
    window.clipboard_clear()
    window.clipboard_append(input)
    messagebox.showinfo("Copied", "Account copied to clipboard!")

def copyPass(window, input):
    window.clipboard_clear()
    window.clipboard_append(input)
    messagebox.showinfo("Copied", "Password copied to clipboard!")

# Initialize the main window

# Center the window before updating and running the main loop
center_window(window)

# Check if master password exists
cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginScreen()
else:
    firstTimeScreen()

window.mainloop()
