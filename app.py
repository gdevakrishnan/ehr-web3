from flask import Flask, request, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField
from wtforms.validators import DataRequired, Email, Length
from web3 import Web3
import json
import os
from datetime import datetime
from cryptography.fernet import Fernet
import hashlib
from dotenv import load_dotenv
from pymongo import MongoClient
import base64

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'default-secret-key')
Bootstrap(app)

MONGODB_URI = os.getenv('MONGODB_URI')
DB_NAME = os.getenv('DB_NAME', 'patient_db')
if not MONGODB_URI:
    raise ValueError("No MongoDB URI found in environment variables")

client = MongoClient(MONGODB_URI)
db = client[DB_NAME]
patients_collection = db.patients
audit_collection = db.audit_logs

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
            except Exception as e:
                flash("Invalid private key. Please double-check your input.", "danger")
            
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

    # # Create audit log for data saving
    # create_audit_log(
    #     action="save_patient_data",
    #     user_id=str(result.inserted_id),
    #     details="Patient data encrypted and stored"
    # )

    result = patients_collection.insert_one(patient_data)
    print(f"Patient data saved successfully with ID: {result.inserted_id}")
    return result.inserted_id
    
    


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

class LogForm(FlaskForm):
    account_address = StringField('Account Address', validators=[DataRequired()])
    contract_address = StringField('Contract Address (If Audit put 0)', validators=[DataRequired()])
    password = PasswordField('Your Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LogForm()
    if form.validate_on_submit():
        input_wallet = form.account_address.data.strip()
        input_contract = form.contract_address.data.strip()
        input_password = form.password.data.strip()
        
        # Search all patient records
        all_patients = patients_collection.find()
        for patient in all_patients:
            try:
                # Decrypt and compare wallet + contract
                decrypted_wallet = fernet.decrypt(patient['patient_wallet_address'].encode()).decode()
                decrypted_contract = fernet.decrypt(patient['contract_address'].encode()).decode()

                if decrypted_wallet == input_wallet and decrypted_contract == input_contract:
                    # Decrypt stored password hash
                    print('hi')
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
                        
                        # Success: render patient dashboard/info
                        return render_template('index.html', patient=decrypted_data)

                    else:
                        flash("Incorrect password. Please try again.", "danger")
                        return redirect(url_for('patient_login'))

            except Exception as e:
                print(f"Error during login matching: {e}")
                continue  # If decryption fails for a record, move on

        flash("Patient not found with the provided credentials.", "danger")
    return render_template('login.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)