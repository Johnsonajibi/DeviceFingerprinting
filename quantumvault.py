
import os
import json
<<<<<<< HEAD
import csv
import base64
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from getpass import getpass
import pandas as pd

VAULT_FILE = "vault.enc"
INFO_FILE = "vault_info.json"
ARCHIVE_FILE = "vault_archive.json"

def derive_key(password):
    salt = b'QuantumVaultSalt'
    digest = hashlib.sha3_512(password.encode()).digest()
    return digest[:32]

def encrypt_data(data, key):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, json.dumps(data).encode(), None)
    return nonce + ciphertext

def decrypt_data(enc_data, key):
    try:
        aesgcm = AESGCM(key)
        nonce = enc_data[:12]
        ciphertext = enc_data[12:]
        return json.loads(aesgcm.decrypt(nonce, ciphertext, None).decode())
    except Exception:
        return None

def save_user(name):
    with open(INFO_FILE, "w") as f:
        json.dump({"name": name}, f)

def save_master_password_hash(password):
    hashed = hashlib.sha3_512(password.encode()).hexdigest()
    with open("vault_master.hash", "w") as f:
        f.write(hashed)

def validate_master_password(input_password):
    try:
        with open("vault_master.hash", "r") as f:
            stored_hash = f.read().strip()
        input_hash = hashlib.sha3_512(input_password.encode()).hexdigest()
        return input_hash == stored_hash
    except FileNotFoundError:
        return False

def setup_vault():
    print("Welcome to QuantumVault - First Time Setup")
    name = input("Enter your name: ").strip()

    print("\nCreate a master password (first time only).")
=======
import base64
import hashlib
import random
import string
from datetime import datetime
import csv
import pandas as pd
from cryptography.fernet import Fernet

VAULT_FILE = "vault.dat"
INFO_FILE = "vault_info.json"

def derive_key(master_password: str) -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(master_password.encode()).digest())

def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(json.dumps(data).encode())

def decrypt_data(ciphertext, key):
    fernet = Fernet(key)
    return json.loads(fernet.decrypt(ciphertext).decode())

def generate_password(length=20) -> str:
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.SystemRandom().choice(characters) for _ in range(length))

def setup_vault():
    print("=== QuantumVault Setup ===")
    name = input("Enter your full name: ").strip()
    print("\nCreate a master password.")
>>>>>>> f72e240d1ad76f6f3dc7a8df7ad2363d3222325b
    print("Tip: Use a memorable sentence at least 30 characters long.")
    while True:
        master_password = input("Master Password: ").strip()
        if len(master_password) < 30:
<<<<<<< HEAD
            print("❗ You have entered less than the required number of characters (30). Please try again.")
        else:
            break

    save_user(name)
    save_master_password_hash(master_password)

    key = derive_key(master_password)
    entries = []

    with open(VAULT_FILE, 'wb') as f:
        f.write(encrypt_data(entries, key))

    return master_password

def load_vault(master_password):
    key = derive_key(master_password)
    try:
        with open(VAULT_FILE, 'rb') as f:
            enc_data = f.read()
        data = decrypt_data(enc_data, key)
        if data is None:
            print("❌ Unable to decrypt vault. Wrong password?")
            return None, key
        return data, key
    except FileNotFoundError:
        return [], key

def save_vault(data, key):
    with open(VAULT_FILE, 'wb') as f:
        f.write(encrypt_data(data, key))

def load_archive():
    if os.path.exists(ARCHIVE_FILE):
        with open(ARCHIVE_FILE, "r") as f:
            return json.load(f)
    return []

def save_archive(archive):
    with open(ARCHIVE_FILE, "w") as f:
        json.dump(archive, f, indent=2)

def add_entry(master_password):
    entries, key = load_vault(master_password)
    archive = load_archive()

    service = input("Service: ").strip()
    username = input("Username: ").strip()
    existing = [e for e in entries if e["service"] == service and e["username"] == username]
    if existing:
        print("This service and username combination already exists.")
        choice = input("Do you want to update the password? (y/n): ").lower()
        if choice != 'y':
            return
        for e in existing:
            archive.append({**e, "archived_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
            entries.remove(e)

    password = base64.urlsafe_b64encode(os.urandom(20)).decode()[:20]
    entries.append({"service": service, "username": username, "password": password})
    print(f"✅ Entry saved. Generated password: {password}")
    save_vault(entries, key)
    save_archive(archive)
    print("✅ Entry saved successfully.")

def view_entries(master_password):
    entries, _ = load_vault(master_password)
    print("\nStored Entries:")
    for entry in entries:
        print(f"{entry['service']} - {entry['username']} - {entry['password']}")

def view_archive():
    archive = load_archive()
    print("\nArchived Passwords:")
    for entry in archive:
        print(f"{entry['service']} - {entry['username']} - {entry['password']} (archived at {entry['archived_at']})")

def import_from_csv(master_password):
    path = input("Enter the CSV file path (service,username,password): ").strip()
    try:
        entries, key = load_vault(master_password)
        archive = load_archive()

        with open(path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            count = 0
            for row in reader:
                service = row['service'].strip()
                username = row['username'].strip()
                password = row['password'].strip()
                if not any(e['service'] == service and e['username'] == username for e in entries):
                    entries.append({'service': service, 'username': username, 'password': password})
                    count += 1
        save_vault(entries, key)
        print(f"Imported {count} new entries from CSV.")
    except Exception as e:
        print(f"Error reading CSV file: {e}")

def import_from_excel(master_password):
    path = input("Enter the Excel file path (.xlsx): ").strip()
    try:
        df = pd.read_excel(path)
        entries, key = load_vault(master_password)
        count = 0
        for _, row in df.iterrows():
            service = row['service'].strip()
            username = row['username'].strip()
            password = row['password'].strip()
            if not any(e['service'] == service and e['username'] == username for e in entries):
                entries.append({'service': service, 'username': username, 'password': password})
                count += 1
        save_vault(entries, key)
        print(f"Imported {count} new entries from Excel.")
=======
            print("Password too short. Try again.")
        else:
            break

    key = derive_key(master_password)
    with open(INFO_FILE, 'w') as f:
        json.dump({"user": name}, f)

    encrypted = encrypt_data([], key)
    with open(VAULT_FILE, 'wb') as f:
        f.write(encrypted)

    print(f"Vault created successfully. Welcome, {name}!")
    return master_password

def load_user():
    if not os.path.exists(INFO_FILE):
        return None
    with open(INFO_FILE, 'r') as f:
        return json.load(f).get("user")

def add_entry(master_password: str):
    key = derive_key(master_password)
    try:
        with open(VAULT_FILE, 'rb') as f:
            encrypted_data = f.read()
        entries = decrypt_data(encrypted_data, key)
    except Exception as e:
        print(f"Error unlocking vault: {e}")
        return

    service = input("Service Name: ").strip()
    username = input("Username/Email: ").strip()

    print("Do you want to generate a secure 20-character password? (yes/no)")
    if input("> ").strip().lower() == "yes":
        password = generate_password()
        print(f"Generated Password: {password}")
    else:
        password = input("Enter Password: ").strip()

    confirm = input("Save this entry? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("Entry discarded.")
        return

    for entry in entries:
        if entry["service"].lower() == service.lower() and entry["username"].lower() == username.lower():
            print(f"An entry for service '{service}' and username '{username}' already exists.")
            update = input("Do you want to update the password? (yes/no): ").strip().lower()
            if update == "yes":
                reuse = input("Use the password you just entered or generate a new one? (use/generate): ").strip().lower()
                if reuse == "generate":
                    password = generate_password()
                    print(f"New Password: {password}")
                old_password = entry["password"]
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                if "history" not in entry:
                    entry["history"] = []
                entry["history"].append({"password": old_password, "changed_at": timestamp})
                entry["password"] = password
                with open(VAULT_FILE, 'wb') as f:
                    f.write(encrypt_data(entries, key))
                print("Password updated and old password archived.")
            else:
                print("No changes made.")
            return

    entries.append({"service": service, "username": username, "password": password})
    with open(VAULT_FILE, 'wb') as f:
        f.write(encrypt_data(entries, key))
    print("Entry saved.")

def view_entries(master_password: str):
    key = derive_key(master_password)
    try:
        with open(VAULT_FILE, 'rb') as f:
            encrypted_data = f.read()
        entries = decrypt_data(encrypted_data, key)
    except Exception as e:
        print(f"Error unlocking vault: {e}")
        return

    if not entries:
        print("Vault is empty.")
    else:
        print("\n=== Stored Entries ===")
        for entry in entries:
            print(f"Service: {entry['service']}, Username: {entry['username']}, Password: {entry['password']}")

def view_history(master_password: str):
    key = derive_key(master_password)
    try:
        with open(VAULT_FILE, 'rb') as f:
            encrypted_data = f.read()
        entries = decrypt_data(encrypted_data, key)
    except Exception as e:
        print(f"Error unlocking vault: {e}")
        return

    print("\n=== Password History ===")
    found = False
    for entry in entries:
        if "history" in entry:
            found = True
            print(f"Service: {entry['service']}, Username: {entry['username']}")
            for record in entry["history"]:
                print(f"  - {record['changed_at']}: {record['password']}")
    if not found:
        print("No history found.")

def import_csv(master_password: str):
    key = derive_key(master_password)
    try:
        if os.path.exists(VAULT_FILE):
            with open(VAULT_FILE, 'rb') as f:
                encrypted_data = f.read()
            entries = decrypt_data(encrypted_data, key)
        else:
            entries = []
    except Exception as e:
        print(f"Error unlocking vault: {e}")
        return

    file_path = input("Enter the CSV file path (service,username,password): ").strip()
    if not os.path.exists(file_path):
        print("CSV file not found.")
        return

    try:
        with open(file_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            imported_count = 0
            for row in reader:
                service = row.get("service")
                username = row.get("username")
                password = row.get("password")
                if service and username and password:
                    exists = any(
                        e["service"].lower() == service.lower() and
                        e["username"].lower() == username.lower() for e in entries
                    )
                    if not exists:
                        entries.append({
                            "service": service,
                            "username": username,
                            "password": password
                        })
                        imported_count += 1
            with open(VAULT_FILE, 'wb') as f:
                f.write(encrypt_data(entries, key))
            print(f"Imported {imported_count} new entries from CSV.")
    except Exception as e:
        print(f"Error reading CSV file: {e}")

def import_excel(master_password: str):
    key = derive_key(master_password)
    try:
        if os.path.exists(VAULT_FILE):
            with open(VAULT_FILE, 'rb') as f:
                encrypted_data = f.read()
            entries = decrypt_data(encrypted_data, key)
        else:
            entries = []
    except Exception as e:
        print(f"Error unlocking vault: {e}")
        return

    file_path = input("Enter the Excel file path (.xlsx): ").strip()
    if not os.path.exists(file_path):
        print("Excel file not found.")
        return

    try:
        df = pd.read_excel(file_path)
        if not {'service', 'username', 'password'}.issubset(df.columns):
            print("Excel file must contain 'service', 'username', and 'password' columns.")
            return

        imported_count = 0
        for _, row in df.iterrows():
            service = str(row['service'])
            username = str(row['username'])
            password = str(row['password'])
            exists = any(
                e["service"].lower() == service.lower() and
                e["username"].lower() == username.lower() for e in entries
            )
            if not exists:
                entries.append({
                    "service": service,
                    "username": username,
                    "password": password
                })
                imported_count += 1

        with open(VAULT_FILE, 'wb') as f:
            f.write(encrypt_data(entries, key))
        print(f"Imported {imported_count} new entries from Excel.")
>>>>>>> f72e240d1ad76f6f3dc7a8df7ad2363d3222325b
    except Exception as e:
        print(f"Error reading Excel file: {e}")

def main():
    if not os.path.exists(VAULT_FILE) or not os.path.exists(INFO_FILE):
        master_password = setup_vault()
    else:
<<<<<<< HEAD
        print("\nEnter your master password to unlock QuantumVault.")
        for attempt in range(3):
            master_password = input("Master Password: ").strip()
            if validate_master_password(master_password):
                print("✅ Access granted.")
                break
            else:
                print("❌ Invalid password. Please try again.")
        else:
            print("🚫 Too many failed attempts. Exiting.")
            return

    while True:
        print("\nOptions:")
        print("1. Add entry")
        print("2. View entries")
        print("3. View archive")
        print("4. Import from CSV")
        print("5. Import from Excel")
        print("6. Exit")
        choice = input("Select an option: ")

        if choice == '1':
            add_entry(master_password)
        elif choice == '2':
            view_entries(master_password)
        elif choice == '3':
            view_archive()
        elif choice == '4':
            import_from_csv(master_password)
        elif choice == '5':
            import_from_excel(master_password)
        elif choice == '6':
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")
=======
        user = load_user()
        print(f"Welcome back, {user}!")
        master_password = input("Enter master password: ").strip()

    while True:
        print("\nChoose an option:")
        print("1. Add a new password")
        print("2. View saved passwords")
        print("3. View password history")
        print("4. Import from CSV")
        print("5. Import from Excel")
        print("6. Exit")
        choice = input("> ").strip()

        if choice == "1":
            add_entry(master_password)
        elif choice == "2":
            view_entries(master_password)
        elif choice == "3":
            view_history(master_password)
        elif choice == "4":
            import_csv(master_password)
        elif choice == "5":
            import_excel(master_password)
        elif choice == "6":
            print("Goodbye!")
            break
        else:
            print("Invalid option. Try again.")
>>>>>>> f72e240d1ad76f6f3dc7a8df7ad2363d3222325b

if __name__ == "__main__":
    main()
