from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField
from wtforms.validators import DataRequired, Email, Length
from web3 import Web3
from bson import json_util
import json
import os
import time
from datetime import datetime
from cryptography.fernet import Fernet
import hashlib
from dotenv import load_dotenv
from pymongo import MongoClient
import random
import string

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'default-secret-key')
Bootstrap(app)

# MongoDB setup
MONGODB_URI = os.getenv('MONGODB_URI')
DB_NAME = os.getenv('DB_NAME', 'ehr_db')
if not MONGODB_URI:
    raise ValueError("No MongoDB URI found in environment variables")

client = MongoClient(MONGODB_URI)
db = client[DB_NAME]
patients_collection = db.patients
users_collection = db.users
audits_collection = db.audits
medical_records = db.medical_records

# Set up Alchemy connection to Sepolia
ALCHEMY_API_KEY = os.getenv('ALCHEMY_API_KEY')
PRIVATE_KEY = os.getenv('PRIVATE_KEY')
alchemy_url = f"https://eth-sepolia.g.alchemy.com/v2/{ALCHEMY_API_KEY}"
w3 = Web3(Web3.HTTPProvider(alchemy_url))

# Check if connected to Ethereum
if w3.is_connected():
    print("Connected to Ethereum network")
else:
    print("Failed to connect to Ethereum network")

# Load bytecode and ABI
try:
    with open('build/bytecode.json', 'r') as f:
        bytecode_json = json.load(f)
        bytecode = bytecode_json['bytecode']

    with open('build/abi.json', 'r') as f:
        abi = json.load(f)
    
    print("Successfully loaded bytecode and ABI")
except Exception as e:
    print(f"Error loading contract files: {e}")
    bytecode = ""
    abi = []

# Set up account from private key
account = w3.eth.account.from_key(PRIVATE_KEY)
account_address = account.address
print(f"Using account: {account_address}")

# Create contract instance
Patient = w3.eth.contract(abi=abi, bytecode=bytecode)

# Set up encryption
def setup_encryption():
    key_path = 'data/enc_key.key'
    
    if not os.path.exists('data'):
        os.makedirs('data')

    def is_valid_fernet_key(key):
        try:
            Fernet(key)
            return True
        except ValueError:
            return False

    key = None
    if os.path.exists(key_path):
        with open(key_path, 'rb') as key_file:
            key = key_file.read()
            if not is_valid_fernet_key(key):
                print("Invalid encryption key found. Regenerating...")
                key = Fernet.generate_key()
                with open(key_path, 'wb') as key_file:
                    key_file.write(key)
            else:
                print("Loaded existing encryption key")
    else:
        key = Fernet.generate_key()
        with open(key_path, 'wb') as key_file:
            key_file.write(key)
        print("Generated new encryption key")

    return Fernet(key)

# Initialize encryption
fernet = setup_encryption()

# Patient Registration Form
class PatientRegForm(FlaskForm):
    name_first = StringField('First Name', validators=[DataRequired(), Length(min=2, max=50)])
    name_last = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=50)])
    IID = StringField('Insurance ID', validators=[DataRequired(), Length(min=5, max=50)])
    bdate = DateField('Birth Date', validators=[DataRequired()], format='%Y-%m-%d')
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone', validators=[DataRequired(), Length(min=10, max=15)])
    zip_code = StringField('ZIP Code', validators=[DataRequired(), Length(min=5, max=10)])
    city = StringField('City', validators=[DataRequired(), Length(min=2, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    private_key = PasswordField('Private Key', validators=[DataRequired(), Length(min=64, max=66)])
    submit = SubmitField('Register')

class LogForm(FlaskForm):
    account_address = StringField('Account Address', validators=[DataRequired()])
    contract_address = StringField('Contract Address (If Audit put 0)', validators=[DataRequired()])
    password = PasswordField('Your Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

class DoctorRegForm(FlaskForm):
    account_address = StringField('Account Address', validators=[DataRequired()])
    name_first = StringField('First Name', validators=[DataRequired()])
    name_last = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email Address', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm = PasswordField('Repeat Password')
    submit = SubmitField('Submit')

class AuditRegForm(FlaskForm):
    account_address = StringField('Account Address', validators=[DataRequired()])
    name_first = StringField('First Name', validators=[DataRequired()])
    name_last = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email Address', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm = PasswordField('Repeat Password')
    submit = SubmitField('Submit')

class UserLoginForm(FlaskForm):
    employee_id = StringField('Employee ID', validators=[DataRequired(), Length(min=6, max=6)])
    account_address = StringField('Account Address', validators=[DataRequired(), Length(min=42, max=42)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

def generate_employee_id():
    """Generate a random employee ID of format aa1234"""
    letters = ''.join(random.choices(string.ascii_lowercase, k=2))
    numbers = ''.join(random.choices(string.digits, k=4))
    return letters + numbers

def is_employee_id_unique(emp_id):
    """Check if the generated employee ID already exists in the DB"""
    users = list(users_collection.find({"$or": [{"user_type": "doctor"}, {"user_type": "audit"}]}))
    for user in users:
        try:
            if 'employee_id' in user:
                decrypted_id = fernet.decrypt(user['employee_id'].encode('utf-8')).decode('utf-8')
                if decrypted_id == emp_id:
                    return False
        except Exception:
            continue
    return True

def add_doctor_to_contract(contract_address, doctor_address):
    """Add a doctor to the deployed patient contract"""
    try:
        # Get contract instance
        contract = w3.eth.contract(address=contract_address, abi=abi)
        
        # Build transaction
        tx = contract.functions.addDoctors(doctor_address).build_transaction({
            'from': account_address,
            'nonce': w3.eth.get_transaction_count(account_address),
            'gas': 2000000,
            'gasPrice': w3.eth.gas_price,
            'chainId': 11155111  # Sepolia chain ID
        })
        
        # Sign transaction
        signed_tx = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
        
        # Send transaction
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        print(f"Doctor add transaction sent: {tx_hash.hex()}")
        
        # Wait for transaction receipt
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        # Check for event
        event_logs = contract.events.event_add_doctor().process_receipt(tx_receipt)
        
        if event_logs:
            event_data = event_logs[0]['args']
            message = event_data[0]  # First arg is the message "A doctor is added."
            doctor_addr = event_data[1]  # Second arg is the doctor address
            timestamp = event_data[2]  # Third arg is the timestamp
            
            return {
                'success': True,
                'message': message,
                'doctor_address': doctor_addr,
                'timestamp': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                'tx_hash': tx_hash.hex()
            }
        
        return {
            'success': True,
            'message': 'Doctor added but no event detected',
            'tx_hash': tx_hash.hex()
        }
    
    except Exception as e:
        print(f"Error adding doctor to contract: {e}")
        return {
            'success': False,
            'message': str(e)
        }

def add_audit_to_contract(contract_address, audit_address):
    """Add an auditor to the deployed patient contract"""
    try:
        # Get contract instance
        contract = w3.eth.contract(address=contract_address, abi=abi)
        
        # Build transaction
        tx = contract.functions.addAudit(audit_address).build_transaction({
            'from': account_address,
            'nonce': w3.eth.get_transaction_count(account_address),
            'gas': 2000000,
            'gasPrice': w3.eth.gas_price,
            'chainId': 11155111  # Sepolia chain ID
        })
        
        # Sign transaction
        signed_tx = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
        
        # Send transaction
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        print(f"Audit add transaction sent: {tx_hash.hex()}")
        
        # Wait for transaction receipt
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        # Check for event
        event_logs = contract.events.event_add_auditor().process_receipt(tx_receipt)
        
        if event_logs:
            event_data = event_logs[0]['args']
            message = event_data[0]  # First arg is the message "An auditor is added."
            audit_addr = event_data[1]  # Second arg is the auditor address
            timestamp = event_data[2]  # Third arg is the timestamp
            
            return {
                'success': True,
                'message': message,
                'audit_address': audit_addr,
                'timestamp': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                'tx_hash': tx_hash.hex()
            }
        
        return {
            'success': True,
            'message': 'Auditor added but no event detected',
            'tx_hash': tx_hash.hex()
        }
    
    except Exception as e:
        print(f"Error adding auditor to contract: {e}")
        return {
            'success': False,
            'message': str(e)
        }

def deploy_patient_contract(first_name, last_name, iid, bdate, email, phone, zip_code, city, encryption_key):
    """Deploy the patient contract to Sepolia"""
    # Create contract constructor transaction
    construct_txn = Patient.constructor(
        first_name, last_name, iid, bdate, 
        email, phone, zip_code, city, encryption_key
    ).build_transaction({
        'from': account_address,
        'nonce': w3.eth.get_transaction_count(account_address),
        'gas': 3000000,  # Increased gas limit for contract deployment
        'gasPrice': w3.eth.gas_price, 
        'chainId': 11155111  # Sepolia chain ID
    })
    
    # Sign transaction
    signed_txn = w3.eth.account.sign_transaction(construct_txn, PRIVATE_KEY)
    
    # Send transaction
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    print(f"Transaction sent: {tx_hash.hex()}")
    
    # Wait for transaction to be mined
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    contract_address = tx_receipt['contractAddress']
    
    return contract_address

def save_patient_data(form, contract_address, patient_wallet_address):
    pass_hash = hashlib.sha224(
        bytes(form.password.data, encoding='utf-8')
    ).hexdigest()
    
    # Encrypt patient data
    patient_data = {
        "user_type": "patient",
        "first_name": fernet.encrypt(form.name_first.data.encode('utf-8')).decode('utf-8'),
        "last_name": fernet.encrypt(form.name_last.data.encode('utf-8')).decode('utf-8'),
        "patient_wallet_address": fernet.encrypt(patient_wallet_address.encode('utf-8')).decode('utf-8'),
        "contract_address": fernet.encrypt(contract_address.encode('utf-8')).decode('utf-8'),
        "email": fernet.encrypt(form.email.data.encode('utf-8')).decode('utf-8'),
        "phone": fernet.encrypt(form.phone.data.encode('utf-8')).decode('utf-8'),
        "city": fernet.encrypt(form.city.data.encode('utf-8')).decode('utf-8'),
        "zip_code": fernet.encrypt(form.zip_code.data.encode('utf-8')).decode('utf-8'),
        "insurance_id": fernet.encrypt(form.IID.data.encode('utf-8')).decode('utf-8'),
        "birth_date": fernet.encrypt(form.bdate.data.strftime('%Y-%m-%d').encode('utf-8')).decode('utf-8'),
        "password_hash": fernet.encrypt(pass_hash.encode('utf-8')).decode('utf-8'),
        "created_at": datetime.now()
    }

    result = patients_collection.insert_one(patient_data)
    print(f"Patient data saved successfully with ID: {result.inserted_id}")
    return result.inserted_id

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/patientreg', methods=['GET', 'POST'])
def patient_registration():
    form = PatientRegForm()
    
    if form.validate_on_submit():
        try:
            # Get form data
            first_name = form.name_first.data
            last_name = form.name_last.data
            iid = form.IID.data
            bdate = form.bdate.data.strftime('%Y-%m-%d')
            email = form.email.data
            phone = form.phone.data
            zip_code = form.zip_code.data
            city = form.city.data

            try:
                patient_account = w3.eth.account.from_key(form.private_key.data)
                patient_wallet_address = patient_account.address
                print(f"Patient wallet address: {patient_wallet_address}")
            except Exception:
                flash("Invalid private key. Please double-check your input.", "danger")
                return redirect(url_for('patient_registration'))
            
            # Generate encryption key for the patient
            encryption_key = Fernet.generate_key().decode('utf-8')
            
            # Deploy smart contract
            contract_address = deploy_patient_contract(
                first_name, last_name, iid, bdate, 
                email, phone, zip_code, city, encryption_key
            )

            # Save encrypted patient data
            save_patient_data(form, contract_address, patient_wallet_address)
            
            # Generate QR code URL with the contract address
            patient_qr = f"https://api.qrserver.com/v1/create-qr-code/?data={contract_address}&size=150x150"
            
            # Log successful registration
            print(f"Patient registered: {first_name} {last_name}")
            print(f"Contract deployed at: {contract_address}")
            
            return render_template(
                'result.html',
                result="Registration successful! Contract deployed.",
                username=f"{first_name} {last_name}",
                address=contract_address,
                tx_hash="View on Etherscan",
                etherscan_link=f"https://sepolia.etherscan.io/address/{contract_address}",
                qr_link=patient_qr
            )
            
        except Exception as e:
            print(f"Error in registration: {str(e)}")
            flash(f"Registration failed: {str(e)}", 'danger')
            
    return render_template('patientreg.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LogForm()
    if form.validate_on_submit():
        input_wallet = form.account_address.data.strip()
        input_contract = form.contract_address.data.strip()
        input_password = form.password.data.strip()
        
        # Search all patient records
        all_patients = patients_collection.find({"user_type": "patient"})
        for patient in all_patients:
            try:
                # Decrypt and compare wallet + contract
                decrypted_wallet = fernet.decrypt(patient['patient_wallet_address'].encode()).decode()
                decrypted_contract = fernet.decrypt(patient['contract_address'].encode()).decode()

                if decrypted_wallet == input_wallet and decrypted_contract == input_contract:
                    # Decrypt stored password hash
                    decrypted_pass_hash = fernet.decrypt(patient['password_hash'].encode()).decode()
                    input_pass_hash = hashlib.sha224(input_password.encode()).hexdigest()
                    
                    if decrypted_pass_hash == input_pass_hash:
                        # Decrypt remaining patient info
                        decrypted_data = {
                            "first_name": fernet.decrypt(patient['first_name'].encode()).decode(),
                            "last_name": fernet.decrypt(patient['last_name'].encode()).decode(),
                            "email": fernet.decrypt(patient['email'].encode()).decode(),
                            "phone": fernet.decrypt(patient['phone'].encode()).decode(),
                            "city": fernet.decrypt(patient['city'].encode()).decode(),
                            "zip_code": fernet.decrypt(patient['zip_code'].encode()).decode(),
                            "insurance_id": fernet.decrypt(patient['insurance_id'].encode()).decode(),
                            "birth_date": fernet.decrypt(patient['birth_date'].encode()).decode(),
                            "wallet_address": decrypted_wallet,
                            "contract_address": decrypted_contract,
                            "created_at": patient['created_at'].strftime('%Y-%m-%d %H:%M:%S')
                        }
                        
                        # store the data in session
                        session['patient_data'] = decrypted_data
                        # Success: render patient dashboard/info
                        return redirect(url_for('dashboard'))

                    else:
                        flash("Incorrect password. Please try again.", "danger")
                        return redirect(url_for('login'))

            except Exception as e:
                print(f"Error during login matching: {e}")
                continue  # If decryption fails for a record, move on

        flash("Patient not found with the provided credentials.", "danger")
    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    data = session.get('patient_data')
    unique_id = session.get('current_visit_id')
    if not data:
        flash("Please login first", "warning")
        return redirect(url_for('login'))
    
    if unique_id:
        return render_template('dashboard.html', patient_data=data, unique_id=unique_id)
    else:
        return render_template('dashboard.html', patient_data=data, unique_id=None)


@app.route('/add-doctor', methods=['GET', 'POST'])
def add_doctor():
    form = DoctorRegForm()
    data = session.get('patient_data')
    
    if not data:
        flash("Please login first", "warning")
        return redirect(url_for('login'))
    
    # Generate unique employee ID
    random_id = generate_employee_id()
    while not is_employee_id_unique(random_id):
        random_id = generate_employee_id()
    
    if form.validate_on_submit():
        try:
            doctor_address = form.account_address.data.strip()
            
            # Hash password
            pass_hash = hashlib.sha224(form.password.data.encode('utf-8')).hexdigest()
            
            # Add doctor to smart contract
            contract_address = data.get('contract_address')
            result = add_doctor_to_contract(contract_address, doctor_address)
            
            if result['success']:
                # Encrypt doctor data
                doctor_data = {
                    "user_type": "doctor",
                    "account_address": fernet.encrypt(doctor_address.encode('utf-8')).decode('utf-8'),
                    "first_name": fernet.encrypt(form.name_first.data.encode('utf-8')).decode('utf-8'),
                    "last_name": fernet.encrypt(form.name_last.data.encode('utf-8')).decode('utf-8'),
                    "email": fernet.encrypt(form.email.data.encode('utf-8')).decode('utf-8'),
                    "employee_id": fernet.encrypt(random_id.encode('utf-8')).decode('utf-8'),
                    "password_hash": fernet.encrypt(pass_hash.encode('utf-8')).decode('utf-8'),
                    "patient_contract": fernet.encrypt(contract_address.encode('utf-8')).decode('utf-8'),
                    "tx_hash": fernet.encrypt(result['tx_hash'].encode('utf-8')).decode('utf-8') if 'tx_hash' in result else "",
                    "created_at": datetime.now()
                }
                
                # Insert into database
                db_result = users_collection.insert_one(doctor_data)
                
                # Provide feedback
                if db_result.inserted_id:
                    flash_message = f"Doctor added successfully! Employee ID: {random_id}"
                    flash(flash_message, 'success')
                    return redirect(url_for('user_dashboard'))
                else:
                    flash('Failed to add doctor to database. Please try again.', 'danger')
            else:
                flash(f'Failed to add doctor to contract: {result["message"]}', 'danger')
                
        except Exception as e:
            print(f"Error adding doctor: {e}")
            flash(f'Error adding doctor: {str(e)}', 'danger')
    
    return render_template('add_doctor.html', form=form, patient_data=data, employee_id=random_id)

@app.route('/add-audit', methods=['GET', 'POST'])
def add_audit():
    form = AuditRegForm()
    data = session.get('patient_data')
    
    if not data:
        flash("Please login first", "warning")
        return redirect(url_for('login'))
    
    # Generate unique employee ID
    random_id = generate_employee_id()
    while not is_employee_id_unique(random_id):
        random_id = generate_employee_id()
    
    if form.validate_on_submit():
        try:
            audit_address = form.account_address.data.strip()
            
            # Hash password
            pass_hash = hashlib.sha224(form.password.data.encode('utf-8')).hexdigest()
            
            # Add auditor to smart contract
            contract_address = data.get('contract_address')
            result = add_audit_to_contract(contract_address, audit_address)
            
            if result['success']:
                # Encrypt auditor data
                audit_data = {
                    "user_type": "audit",
                    "account_address": fernet.encrypt(audit_address.encode('utf-8')).decode('utf-8'),
                    "first_name": fernet.encrypt(form.name_first.data.encode('utf-8')).decode('utf-8'),
                    "last_name": fernet.encrypt(form.name_last.data.encode('utf-8')).decode('utf-8'),
                    "email": fernet.encrypt(form.email.data.encode('utf-8')).decode('utf-8'),
                    "employee_id": fernet.encrypt(random_id.encode('utf-8')).decode('utf-8'),
                    "password_hash": fernet.encrypt(pass_hash.encode('utf-8')).decode('utf-8'),
                    "patient_contract": fernet.encrypt(contract_address.encode('utf-8')).decode('utf-8'),
                    "tx_hash": fernet.encrypt(result['tx_hash'].encode('utf-8')).decode('utf-8') if 'tx_hash' in result else "",
                    "created_at": datetime.now()
                }
                
                # Insert into database
                db_result = users_collection.insert_one(audit_data)
                
                # Provide feedback
                if db_result.inserted_id:
                    flash_message = f"Auditor added successfully! Employee ID: {random_id}"
                    flash(flash_message, 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Failed to add auditor to database. Please try again.', 'danger')
            else:
                flash(f'Failed to add auditor to contract: {result["message"]}', 'danger')
                
        except Exception as e:
            print(f"Error adding auditor: {e}")
            flash(f'Error adding auditor: {str(e)}', 'danger')
    
    return render_template('add_audit.html', form=form, patient_data=data, employee_id=random_id)

@app.route('/user-login', methods=['GET', 'POST'])
def user_login():
    form = UserLoginForm()
    
    if form.validate_on_submit():
        try:
            # Get form data
            input_employee_id = form.employee_id.data.strip()
            input_account_address = form.account_address.data.strip()
            input_password = form.password.data
            
            # Hash the password for comparison
            input_pass_hash = hashlib.sha224(input_password.encode()).hexdigest()
            
            # Search all users (doctors and auditors)
            all_users = users_collection.find({"$or": [{"user_type": "doctor"}, {"user_type": "audit"}]})
            
            for user in all_users:
                try:
                    # Decrypt stored employee ID and account address
                    decrypted_employee_id = fernet.decrypt(user['employee_id'].encode()).decode()
                    decrypted_account = fernet.decrypt(user['account_address'].encode()).decode()
                    
                    if decrypted_employee_id == input_employee_id and decrypted_account == input_employee_id:
                        # Error check - this shouldn't happen in normal operation
                        flash("Data integrity issue detected. Please contact support.", "danger")
                        return redirect(url_for('user_login'))
                        
                    # Match employee ID and account address
                    if decrypted_employee_id == input_employee_id and decrypted_account == input_account_address:
                        # Decrypt password hash and compare
                        decrypted_pass_hash = fernet.decrypt(user['password_hash'].encode()).decode()
                        
                        if decrypted_pass_hash == input_pass_hash:
                            # User authenticated, decrypt all user data
                            user_data = {
                                "user_type": user['user_type'],
                                "first_name": fernet.decrypt(user['first_name'].encode()).decode(),
                                "last_name": fernet.decrypt(user['last_name'].encode()).decode(),
                                "email": fernet.decrypt(user['email'].encode()).decode(),
                                "employee_id": decrypted_employee_id,
                                "account_address": decrypted_account,
                                "patient_contract": fernet.decrypt(user['patient_contract'].encode()).decode(),
                                "created_at": user['created_at'].strftime('%Y-%m-%d %H:%M:%S')
                            }
                            
                            # If there's a tx_hash field, decrypt it
                            if 'tx_hash' in user:
                                user_data["tx_hash"] = fernet.decrypt(user['tx_hash'].encode()).decode()
                            
                            # Store decrypted data in session
                            session['user_data'] = user_data
                            
                            # Redirect to user dashboard
                            flash(f"Welcome, {user_data['first_name']} {user_data['last_name']}!", "success")
                            return redirect(url_for('user_dashboard'))
                        else:
                            flash("Incorrect password. Please try again.", "danger")
                            return redirect(url_for('user_login'))
                
                except Exception as e:
                    print(f"Error during user login matching: {e}")
                    continue  # If decryption fails for a record, move on
            
            flash("User not found with the provided credentials.", "danger")
            
        except Exception as e:
            print(f"Error in user login: {str(e)}")
            flash(f"Login error: {str(e)}", "danger")
    
    return render_template('user_login.html', form=form)

@app.route('/user-dashboard', methods=['GET'])
def user_dashboard():
    user_data = session.get('user_data')
    if not user_data:
        flash("Please login first", "warning")
        return redirect(url_for('user_login'))
    
    return render_template('user_dashboard.html', user_data=user_data)

@app.route('/visit-hospital', methods=['GET', 'POST'])
def visit_hospital():
    try:
        data = session.get('patient_data')
        if not data:
            flash("Please login first", "warning")
            return redirect(url_for('login'))

        # Generate a unique 6-digit ID
        unique_id = None
        while True:
            potential_id = ''.join(random.choices('0123456789', k=6))
            if not medical_records.find_one({"unique_id": potential_id}):
                unique_id = potential_id
                break

        current_time = int(time.time())

        contract_address = Web3.to_checksum_address(data['contract_address'])
        contract = w3.eth.contract(address=contract_address, abi=abi)

        # Build the transaction
        txn = contract.functions.start_visit(current_time, int(unique_id)).build_transaction({
            'from': account_address,
            'nonce': w3.eth.get_transaction_count(account_address),
            'gas': 300000,
            'gasPrice': w3.to_wei('10', 'gwei'),
        })

        if (txn):
            medical_records_data = {
                "unique_id": unique_id,
                "account_address": account_address,
                "patient_contract": contract_address,

                "record_msg": fernet.encrypt("New Medical Record is created".encode('utf-8')).decode('utf-8'),
                "record_details": fernet.encrypt("Visit initiate".encode('utf-8')).decode('utf-8'),
                "doctor_address": fernet.encrypt("".encode('utf-8')).decode('utf-8'),
                "audit_address": fernet.encrypt("".encode('utf-8')).decode('utf-8'),

                "created_at": datetime.now()
            }
            session['current_visit_id'] = unique_id
            result = medical_records.insert_one(medical_records_data)
            print(f"Patient data saved successfully with ID: {result.inserted_id}")
            flash("A new visit was created successfully.", "success")
            return redirect(url_for('dashboard'))
        else:
            raise ValueError("Transaction failed.")

    except Exception as e:
        print(f"Error during /visit-hospital: {e}")
        flash(f"An error occurred: {str(e)}", "danger")
        return redirect(url_for('dashboard'))

@app.route('/records', methods=['GET'])
def records():
    try:
        data = session.get('patient_data')
        if not data:
            flash("Please login first", "warning")
            return redirect(url_for('login'))
        
        user_medical_record_raw = medical_records.find({'patient_contract': data['contract_address']})
        user_medical_record_json_str = json_util.dumps(user_medical_record_raw)
        user_medical_record_dict = json.loads(user_medical_record_json_str)

        user_medical_record = []

        for item in user_medical_record_dict:
            user_medical_record.append({
                "_id": item["_id"]["$oid"],
                "unique_id": item["unique_id"],
                "patient_contract": item["patient_contract"],
                "record_msg": fernet.decrypt(item["record_msg"].encode('utf-8')).decode('utf-8'),
                "record_details": fernet.decrypt(item["record_details"].encode('utf-8')).decode('utf-8'),
                "doctor_address": fernet.decrypt(item["doctor_address"].encode('utf-8')).decode('utf-8'),
                "audit_address": fernet.decrypt(item["audit_address"].encode('utf-8')).decode('utf-8'),
                "created_at": item["created_at"]["$date"]
            })

        return render_template('medical_records.html', patient_data=data, data=user_medical_record)
    
    except Exception as e:
        print(f"Error during /records: {e}")
        flash(f"An error occurred: {str(e)}", "danger")
        return redirect(url_for('dashboard'))

@app.route('/profile', methods=['GET'])
def profile ():
    try:
        data = session.get('patient_data')
        if not data:
            flash("Please login first", "warning")
            return redirect(url_for('login'))
        
        return render_template('profile.html', patient_data=data)
    
    except Exception as e:
        print(f"Error during /profile: {e}")
        flash(f"An error occurred: {str(e)}", "danger")
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)