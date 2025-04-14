import json
import os
import solcx

def compile_contract():
    # Set the path to the contract
    contract_path = os.path.join('contracts', 'patient.sol')
    
    # Check if file exists
    if not os.path.exists(contract_path):
        raise FileNotFoundError(f"Contract file not found at {contract_path}")
    
    # Install specific Solidity compiler version if not already installed
    try:
        solcx.install_solc('0.8.0')
        print("Solidity compiler 0.8.0 installed successfully")
    except Exception as e:
        print(f"Note: {e}")
        print("Proceeding with already installed version.")
    
    # Set the Solidity compiler version
    solcx.set_solc_version('0.8.0')
    print("Using Solidity compiler version 0.8.0")
    
    # Read the contract file
    with open(contract_path, 'r') as file:
        source_code = file.read()
        print(f"Contract loaded from {contract_path}")
    
    # Compile the contract
    print("Compiling contract...")
    compiled_sol = solcx.compile_source(
        source_code,
        output_values=['abi', 'bin'],
        solc_version='0.8.0'
    )
    
    # Extract the contract interface data
    # The key is in the format '<source_file>:<contract_name>'
    contract_id, contract_interface = compiled_sol.popitem()
    print(f"Contract {contract_id} compiled successfully")
    
    # Extract bytecode and ABI
    bytecode = contract_interface['bin']
    abi = contract_interface['abi']
    
    # Create output directory if it doesn't exist
    output_dir = 'build'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Created output directory: {output_dir}")
    
    # Save bytecode to a file
    bytecode_path = os.path.join(output_dir, 'bytecode.json')
    with open(bytecode_path, 'w') as f:
        json.dump({"bytecode": bytecode}, f, indent=4)
    print(f"Bytecode saved to {bytecode_path}")
    
    # Save ABI to a file
    abi_path = os.path.join(output_dir, 'abi.json')
    with open(abi_path, 'w') as f:
        json.dump(abi, f, indent=4)
    print(f"ABI saved to {abi_path}")
    
    return bytecode, abi

if __name__ == "__main__":
    try:
        bytecode, abi = compile_contract()
        print("Compilation complete. Bytecode and ABI saved to JSON files.")
    except Exception as e:
        print(f"Error during compilation: {e}")