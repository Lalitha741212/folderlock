import tkinter as tk
from tkinter import filedialog, messagebox, Button, Frame
import win32com.client
from subprocess import call
import os
from pythoncom import IID_IPersistFile, CoCreateInstance, CLSCTX_INPROC_SERVER
from win32com.shell import shell
from tkinter import simpledialog
import hashlib

folder_path = ""
password_hash = ""  # Store hashed password
locked_folder_hash = ""
password = ""

def hash_password(password):
    # Hash the password using SHA-256
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

"""def hash_password(password):
    # Hash the password using SHA-256
    return hashlib.sha256(password.encode()).hexdigest()"""

def lock(path, password_hash):
    global locked_folder_hash
    call(["attrib", "+H", "+S", "+R", path])
    lock_file = os.path.join(folder_path, '.lock')
    with open(lock_file, 'w') as f:
        f.write(password_hash)#hash_password(password))  # Store the hashed password
        locked_folder_hash = hash_password(password)
    return path

def unlock(name):
    entered_password = simpledialog.askstring("Enter Password", "Enter the password:")
    if entered_password:
        # Construct the path to the .vbs file
        home = os.path.expanduser("~")
        vbs_file_path = os.path.join(home, f"{name}_sky9262.vbs")
        
        # Check if the .vbs file exists
        if os.path.exists(vbs_file_path):
            with open(vbs_file_path) as f:
                first_line = f.readline()
                main_folder = (
                    first_line.replace("REM ", "").replace("\n", "").replace("\\\\", "\\")
                )

            lock_file = os.path.join(main_folder, '.lock')

            if os.path.exists(lock_file):
                stored_hash = ""
                with open(lock_file, 'r') as f:
                    stored_hash = f.read().strip()

                if hash_password(entered_password) == stored_hash:  # Compare entered password hash with stored hash
                    shortcut_path = main_folder + ".lnk"
                    call(["attrib", "-H", "-S", "-R", main_folder])
                    call(["attrib", "-H", "-S", "-R", vbs_file_path])

                    os.remove(shortcut_path)
                    os.remove(vbs_file_path)
                    refresh_buttons()
                    #os.system(f'explorer "{main_folder}"')
                else:
                    messagebox.showerror("Error", "Wrong password!")
            else:
                messagebox.showerror("Error", "Folder is not locked!")
        else:
            messagebox.showerror("Error", "VBS file not found!")
    else:
        messagebox.showerror("Error", "Password cannot be empty!")


"""def unlock(name):
    global locked_folder_hash
    entered_password = simpledialog.askstring("Enter Password", "Enter the password:")
    if entered_password:
        home = os.path.expanduser("~")
        vbs_file_path = f"{home}\\{name}_sky9262.vbs"
        with open(vbs_file_path) as f:
            first_line = f.readline()
            main_folder = (
                first_line.replace("REM ", "").replace("\n", "").replace("\\\\", "\\")
            )

        shortcut_path = main_folder + ".lnk"
        call(["attrib", "-H", "-S", "-R", main_folder])
        call(["attrib", "-H", "-S", "-R", vbs_file_path])

        #os.remove(shortcut_path)
        os.remove(vbs_file_path)
        if hash_password(entered_password) == locked_folder_hash:
            refresh_buttons()
        else:
            messagebox.showerror("Error", "Wrong password!")
    else:
        messagebox.showerror("Error", "Password cannot be empty!")

# ... (other parts of your code remain the same)"""



"""def hash_password(password):
    # Hash the password using SHA-256
    return hashlib.sha256(password.encode()).hexdigest()

def lock(path):
    global password_hash
    call(["attrib", "+H", "+S", "+R", path])
    lock_file = os.path.join(folder_path, '.lock')
    with open(lock_file, 'w') as f:
        f.write(password_hash)
    return path

def unlock(name):
    global password_hash
    entered_password = simpledialog.askstring("Enter Password", "Enter the password:")
    if entered_password:
        home = os.path.expanduser("~")
        vbs_file_path = f"{home}\\{name}_sky9262.vbs"
        with open(vbs_file_path) as f:
            first_line = f.readline()
            main_folder = (
                first_line.replace("REM ", "").replace("\n", "").replace("\\\\", "\\")
            )

        shortcut_path = main_folder + ".lnk"
        call(["attrib", "-H", "-S", "-R", main_folder])
        call(["attrib", "-H", "-S", "-R", vbs_file_path])

        os.remove(shortcut_path)
        os.remove(vbs_file_path)
        refresh_buttons()
    else:
        messagebox.showerror("Error", "Password cannot be empty!")"""

def change_icon(shortcut_path, icon_index=165):
    shell_obj = win32com.client.Dispatch("WScript.Shell")
    shortcut = shell_obj.CreateShortCut(shortcut_path)
    shortcut.IconLocation = f"%SystemRoot%\\system32\\imageres.dll,{icon_index}"
    shortcut.Save()



def createVBS(folder_path):
    global password_hash
    if password_hash == "":
        messagebox.showerror("Error", "Please set a password first.")
        return
    
    home_dir = os.path.expanduser("~")
    folder_name = folder_path.split("\\")[-1]
    vbs_folder_path = folder_path.replace("\\\\", "\\")

    filename = os.path.join(home_dir, f"{folder_name}_sky9262.vbs")
    contents = f"""REM {folder_path}
Dim sInput
sInput = InputBox("Enter the Password", "Password Required - sky9262")
If sInput = "{password}" Then
    MsgBox "Correct Password. Please wait...", vbSystemModal, "Successful - sky9262"
    Set objShell = CreateObject("Shell.Application") 
    strPath = "{vbs_folder_path}"
    objShell.Explore strPath 
Else
    MsgBox "Wrong password!!!", vbSystemModal, "Failed - sky9262"
End If"""

    with open(filename, "w") as f:
        f.write(contents)
    lock(filename,password_hash)
    return filename

# ... (other parts of your code remain the same)

def create_shortcut(file_path, shortcut_path):
    file_name = file_path.split("\\")[-1].replace(".vbs", "")
    shortcut = CoCreateInstance(
        shell.CLSID_ShellLink, None, CLSCTX_INPROC_SERVER, shell.IID_IShellLink
    )
    shortcut.SetPath(file_path)
    shortcut.SetDescription("LockFolder - sky9262")
    shortcut.SetIconLocation("%SystemRoot%\\system32\\imageres.dll", 165)

    persist_file = shortcut.QueryInterface(IID_IPersistFile)
    persist_file.Save(os.path.join(shortcut_path + ".lnk"), 0)


def choose_folder():
    global folder_path,password_hash
    folder_path = filedialog.askdirectory().replace("/", "\\\\")
    folder_path_entry.delete(0, tk.END)
    folder_path_entry.insert(0, folder_path)
    password_hash = hash_password(password)


def check_password():
    global password, password_hash
    entered_password = password_entry.get()
    confirm_password = confirm_password_entry.get()
    if entered_password == "" or confirm_password == "":
        messagebox.showerror("Error", "Password cannot be empty!")
    elif entered_password == confirm_password:
        password = entered_password
        password_hash = hash_password(password)  # Hash the password
        create_shortcut(createVBS(lock(folder_path,password_hash)), folder_path)
        messagebox.showinfo("Success", "Locked!")
        root.destroy()
    else:
        messagebox.showerror("Error", "Passwords do not match!")

# ... (other parts of your code remain the same)
def create_button(filename):
    button = Button(
        frame,
        text=filename,
        command=lambda: unlock(filename),
        bg="#e74c3c",
        fg="#ecf0f1",
        font=("Arial", 10),
    )
    button.pack(padx=10, pady=10, side=tk.BOTTOM)


def refresh_buttons():
    for widget in frame.winfo_children():
        widget.destroy()
    for filename in os.listdir(os.path.expanduser("~")):
        if "sky9262" in filename:
            create_button(filename.replace("_sky9262.vbs", ""))
    
    hidden_folders = len(list(filter(lambda x: "sky9262" in x, os.listdir(os.path.expanduser("~")))))
    root.geometry(f"{win_width}x{win_height + int(hidden_folders)*30}")


def show_files():
    refresh_buttons()

root = tk.Tk()
root.title("Lock Folder - sky9262")

root.configure(bg="#2c3e50")

frame = Frame(root, bg="#2c3e50")
frame.pack(padx=10, pady=10)

win_width = 400
win_height = 350

root.geometry(f"{win_width}x{win_height}")

folder_path_label = tk.Label(
    root, text="Select Folder:", bg="#2c3e50", fg="#ecf0f1", font=("Arial", 12)
)
folder_path_entry = tk.Entry(root, width=50)
folder_path_button = tk.Button(
    root,
    text="Browse",
    command=choose_folder,
    bg="#3498db",
    fg="#ecf0f1",
    font=("Arial", 10),
)

password_label = tk.Label(
    root, text="Password:", bg="#2c3e50", fg="#ecf0f1", font=("Arial", 12)
)
password_entry = tk.Entry(root, width=20, show="*")

confirm_password_label = tk.Label(
    root, text="Confirm Password:", bg="#2c3e50", fg="#ecf0f1", font=("Arial", 12)
)
confirm_password_entry = tk.Entry(root, width=20, show="*")

submit_button = tk.Button(
    root,
    text="Lock",
    command=check_password,
    bg="#27ae60",
    fg="#ecf0f1",
    font=("Arial", 10),
)

# add widgets to the window
folder_path_label.pack(pady=(0, 5))
folder_path_entry.pack(pady=(0, 5))
folder_path_button.pack(pady=(0, 10))

password_label.pack(pady=(0, 5))
password_entry.pack(pady=(0, 5))

confirm_password_label.pack(pady=(0, 5))
confirm_password_entry.pack(pady=(0, 5))

submit_button.pack(pady=(0, 10))

unlock_button = tk.Button(
    root,
    text="Unlock",
    command=show_files,
    bg="#e74c3c",
    fg="#ecf0f1",
    font=("Arial", 10),
)
unlock_button.pack(side=tk.BOTTOM)

# run the main loop
#root.iconbitmap(r".\\winLock.ico")
root.mainloop()


