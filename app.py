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

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'default-secret-key')
Bootstrap(app)

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
    # Generate key if not exists
    key_path = 'data/enc_key.key'
    if not os.path.exists('data'):
        os.makedirs('data')
    
    if not os.path.exists(key_path):
        key = Fernet.generate_key()
        with open(key_path, 'wb') as key_file:
            key_file.write(key)
        print("Generated new encryption key")
    else:
        with open(key_path, 'rb') as key_file:
            key = key_file.read()
        print("Loaded existing encryption key")
    
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
            
            # Generate encryption key for the patient
            encryption_key = Fernet.generate_key().decode('utf-8')
            
            # Save encrypted patient data
            save_patient_data(form, encryption_key)
            
            # Deploy smart contract
            contract_address = deploy_patient_contract(
                first_name, last_name, iid, bdate, 
                email, phone, zip_code, city, encryption_key
            )
            
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
                patient_qr=patient_qr
            )
            
        except Exception as e:
            print(f"Error in registration: {str(e)}")
            flash(f"Registration failed: {str(e)}", 'danger')
            
    return render_template('patientreg.html', form=form)

def save_patient_data(form, encryption_key):
    """Encrypt and save patient data to a file"""
    # Create data directory if it doesn't exist
    if not os.path.exists('data'):
        os.makedirs('data')
    
    # Hash password for storage
    pass_hash = hashlib.sha224(
        bytes("loremipsum" + form.password.data, encoding='utf-8')
    ).hexdigest()
    
    # Encrypt patient data
    encrypted_data = "patient" + ", " + \
        str(fernet.encrypt(b"patient")) + ", " + \
        str(fernet.encrypt(form.name_first.data.encode('utf-8'))) + ", " + \
        str(fernet.encrypt(form.name_last.data.encode('utf-8'))) + ", " + \
        str(fernet.encrypt(form.email.data.encode('utf-8'))) + ", " + \
        str(fernet.encrypt(form.phone.data.encode('utf-8'))) + ", " + \
        str(fernet.encrypt(form.city.data.encode('utf-8'))) + ", " + \
        str(fernet.encrypt(form.zip_code.data.encode('utf-8'))) + ", " + \
        str(fernet.encrypt(form.IID.data.encode('utf-8'))) + ", " + \
        str(fernet.encrypt(pass_hash.encode('utf-8'))) + ", " + \
        str(encryption_key) + "\n"
    
    # Save to file
    fname = hashlib.sha224(b"signin_data").hexdigest()
    with open(f"data/{fname}.csv", "a") as f:
        f.write(encrypted_data)
    
    print("Patient data saved successfully")

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

if __name__ == '__main__':
    app.run(debug=True)