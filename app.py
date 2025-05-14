# app.py

import os
import json # Keep json import just in case
import base64 # Keep base64 for session handling
from flask import Flask, render_template, request, redirect, url_for, session, flash
# Ensure this import matches your strength checker filename exactly
from Password_strength_checker import evaluate_password, generate_suggestive_password, provide_improvement_tips

# Import hashing, checking, and the NEW password manager functions
from password_encryptor import hash_password_bcrypt, check_password_bcrypt
from password_manager import ( # Import manager functions and constants
    is_vault_initialized, # Use the DB check
    initialize_vault,
    unlock_vault,
    get_password_entries,
    add_password_entry,
    derive_key,
    verify_key,
    get_mongo_client # Import to check DB connection status
)


app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# --- Keep index route ---
@app.route('/', methods=['GET', 'POST'])
def index():
    feedback = None
    suggest_password = None
    password_score = None
    breach_count = None
    improvement_tips = None

    if request.method == 'POST':
        password = request.form.get('password')
        if password:
            is_valid, strength, score, feedback_list, breach_count = evaluate_password(password)
            password_score = f"{strength} ({score}/100)"
            feedback = feedback_list
            improvement_tips = provide_improvement_tips(score, breach_count)
            if not is_valid and breach_count == 0:
                 suggest_password = generate_suggestive_password()
        else:
             flash("- Please enter a password to check.", "warning")
             feedback = None

    flashed_messages = session.pop('_flashes', [])

    return render_template(
        'index.html',
        feedback=feedback,
        score=password_score,
        suggest_password=suggest_password,
        breach_count=breach_count,
        improvement_tips=improvement_tips,
        flashed_messages=flashed_messages
    )

# --- Keep encrypt_password route ---
@app.route('/encrypt-password', methods=['GET', 'POST'])
def encrypt_password():
    print("\n--- Inside encrypt_password route ---")
    print(f"Request method: {request.method}")

    original_password_hashed_display = None
    hashed_password_str = None
    password_attempt = None
    hash_to_verify_input = None
    verification_result = None
    status_message = None
    status_type = None

    if request.method == 'POST':
        password_to_hash = request.form.get('password_hash')
        password_attempt_input = request.form.get('password_attempt')
        hash_to_verify_input = request.form.get('hash_to_verify')

        print(f"Value of 'password_hash' in form: '{password_to_hash}'")
        print(f"Value of 'password_attempt' in form: '{password_attempt_input}'")
        print(f"Value of 'hash_to_verify' in form: '{hash_to_verify_input}'")

        if password_to_hash is not None and password_to_hash != "":
            print("Detected hashing request.")
            original_password_hashed_display = '*' * len(password_to_hash) if password_to_hash else ''
            try:
                hashed_bytes = hash_password_bcrypt(password_to_hash)
                hashed_password_str = hashed_bytes.decode('utf-8')
                print(f"Hashing successful. Generated hash: {hashed_password_str[:20]}...")
                status_message = "Password hashed successfully."
                status_type = "success"
            except Exception as e:
                print(f"Error during hashing: {e}")
                hashed_password_str = f"Error during hashing: {e}"
                original_password_hashed_display = None
                status_message = f"Error during hashing: {e}"
                status_type = "error"

        elif password_attempt_input is not None and password_attempt_input != "" and hash_to_verify_input is not None and hash_to_verify_input != "":
            print("Detected verification request.")
            password_attempt = password_attempt_input
            try:
                hashed_bytes_to_verify = hash_to_verify_input.encode('utf-8')
                verification_result = check_password_bcrypt(password_attempt, hashed_bytes_to_verify)
                print(f"Verification performed. Result: {verification_result}")
                status_message = "Verification complete."
                status_type = "success" if verification_result else "error"
            except Exception as e:
                 print(f"Error during verification: {e}")
                 verification_result = False
                 status_message = f"Error during verification: {e}"
                 status_type = "error"
        else:
             status_message = "Please enter values in the form."
             status_type = "warning"

    print("Rendering encrypt.html...")
    flashed_messages = session.pop('_flashes', [])
    return render_template(
        'encrypt.html',
        original_password_hashed=original_password_hashed_display,
        hashed_password=hashed_password_str,
        password_attempt=password_attempt,
        hash_to_verify=hash_to_verify_input,
        verification_result=verification_result,
        status_message=status_message,
        status_type=status_type,
        flashed_messages=flashed_messages
    )

# --- NEW ROUTE for Password Manager (Updated for MongoDB) ---
@app.route('/password-manager', methods=['GET', 'POST'])
def password_manager():
    """
    Handles the password manager page states (initialize, unlock, unlocked).
    Uses session to maintain unlocked state. Interacts with MongoDB.
    """
    status_message = None
    status_type = None

    # --- Check MongoDB Connection ---
    if not get_mongo_client():
        # If connection fails, redirect to error page or show error on this page
        flash("Error: Could not connect to the database. Please check configuration.", "error")
        # Setting states to False might not work if template relies on vault_initialized check first
        # Let's just rely on flash message and return the template state based on no vault found
        vault_initialized = False
        vault_unlocked = False
        password_entries = None
        # Fetch flash messages immediately if DB connection fails on GET
        flashed_messages = session.pop('_flashes', [])
        return render_template(
            'password_manager.html',
            vault_initialized=vault_initialized,
            vault_unlocked=vault_unlocked,
            password_entries=password_entries,
            status_message=None, # Status message usually from POST, flash for connection
            status_type=None,
            flashed_messages=flashed_messages
        )


    # --- Check if Vault Document Exists in DB ---
    vault_initialized = is_vault_initialized()

    # --- Check if Vault is Unlocked (Key in Session) ---
    # The derived key (bytes) stored in session is base64 encoded.
    encryption_key_b64 = session.get('encryption_key')
    vault_unlocked = encryption_key_b64 is not None

    # Decode the key from session if it exists
    encryption_key = None
    if vault_unlocked:
        try:
            encryption_key = base64.b64decode(encryption_key_b64)
            # Although we don't re-verify master password here, ensure the vault document exists
            # and seems valid to use the session key.
            if not is_vault_initialized(): # Check if vault still exists in DB
                 print("Vault document missing while key is in session. Forcing lock.")
                 vault_unlocked = False
                 session.pop('encryption_key', None)
                 flash("Vault data missing from database. Please re-initialize if necessary.", "error")
            # Optional: Add more checks here if the structure loaded from DB seems invalid
            # vault_data_check = load_vault_from_db()
            # if not vault_data_check or 'kdf_salt' not in vault_data_check: ... force lock
        except Exception as e:
            print(f"Error decoding session key or checking vault: {e}. Forcing lock.")
            vault_unlocked = False
            session.pop('encryption_key', None)
            flash("Session key error. Please re-unlock the vault.", "error")


    # --- Handle POST Requests ---
    if request.method == 'POST':
        action = request.form.get('action')
        print(f"Password Manager POST action: {action}")

        if action == 'initialize_vault':
            master_password = request.form.get('master_password')
            master_password_confirm = request.form.get('master_password_confirm')

            # Client-side check is good, but also validate server-side
            if master_password and master_password == master_password_confirm:
                print("Initializing vault...")
                if initialize_vault(master_password):
                    flash("Vault initialized successfully! Please unlock.", "success")
                    return redirect(url_for('password_manager')) # PRG pattern
                else:
                    # initialize_vault returns False if vault already exists or DB fails
                    # is_vault_initialized check handles already exists, so failure is likely DB error
                    flash("Vault initialization failed. Database error.", "error")
                    # If initialization failed, vault_initialized state might be inconsistent
                    vault_initialized = is_vault_initialized() # Re-check state

            else:
                flash("Master passwords do not match or were not provided.", "warning")

        elif action == 'unlock_vault':
            master_password = request.form.get('master_password')
            if master_password:
                print("Attempting to unlock vault...")
                derived_key = unlock_vault(master_password)
                if derived_key:
                    # Store the derived key (base64 encoded) in the session
                    session['encryption_key'] = base64.b64encode(derived_key).decode('utf-8')
                    # vault_unlocked = True # State will be updated by redirect
                    flash("Vault unlocked successfully!", "success")
                    return redirect(url_for('password_manager')) # PRG pattern
                else:
                    # unlock_vault returns None on incorrect password or DB error
                    # We can't easily distinguish here, display a generic error
                    flash("Unlock failed. Incorrect master password or database error.", "error")

            else:
                flash("Please enter the master password.", "warning")

        elif action == 'add_entry': # Removed vault_unlocked check here, let function handle it
            name = request.form.get('name')
            username = request.form.get('username')
            password_entry = request.form.get('password')

            # Ensure vault is actually unlocked and key is in session before attempting add
            if vault_unlocked and encryption_key:
                 if name and username and password_entry:
                    print("Adding entry...")
                    if add_password_entry(encryption_key, name, username, password_entry):
                        flash("Entry added successfully!", "success")
                        return redirect(url_for('password_manager')) # PRG pattern
                    else:
                        # add_password_entry returns False on DB error or failure to load/decrypt
                        flash("Failed to add entry. Database or decryption error.", "error")
                 else:
                    flash("Please fill out all fields to add an entry.", "warning")
            else:
                # This case indicates a POST to add_entry without a valid session key
                flash("Vault is locked. Please unlock to add entries.", "warning")
                return redirect(url_for('password_manager')) # Go back to locked state

        elif action == 'lock_vault' and vault_unlocked:
            print("Locking vault...")
            session.pop('encryption_key', None) # Remove the key from session
            # vault_unlocked = False # State will be updated by redirect
            flash("Vault locked.", "success")
            return redirect(url_for('password_manager')) # PRG pattern

        else:
            # Catch unexpected POST actions or states
            flash("Invalid action or vault state.", "error")
            # Redirect to clean up state
            return redirect(url_for('password_manager'))


    # --- Handle GET Requests and POSTs that don't redirect ---

    # If unlocked, get the password entries for display
    password_entries = None
    if vault_unlocked and encryption_key:
        password_entries = get_password_entries(encryption_key)
        if password_entries is None:
            # If getting entries failed *after* unlock, something is wrong (e.g., data corrupt or DB read failed)
            print("Failed to retrieve password entries despite session key. Forcing lock.")
            session.pop('encryption_key', None)
            vault_unlocked = False
            flash("Could not decrypt vault data. Vault locked. Data may be corrupted or database read failed.", "error")


    # Render the template based on current state
    # Fetch flash messages again if a non-redirecting POST occurred or this is a GET after redirect
    flashed_messages = session.pop('_flashes', [])


    return render_template(
        'password_manager.html',
        vault_initialized=vault_initialized,
        vault_unlocked=vault_unlocked,
        password_entries=password_entries,
        status_message=None, # Status handled by flash for redirects
        status_type=None,    # Status handled by flash for redirects
        flashed_messages=flashed_messages # Pass flash messages
    )


# --- Keep the __main__ block ---
if __name__ == '__main__':
    # Ensure 'templates' directory exists where this script is run from
    if not os.path.exists('templates'):
        os.makedirs('templates')
    # Ensure the connection is attempted on startup for immediate feedback
    # get_mongo_client() # Optional: Attempt connection here to see failure early
    app.run(debug=True)