// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Patient {
    
    /////////////// VARIABLES ///////////////////
    address owner;
    
    // Identity
    string private firstName;
    string private lastName;
    string private IID;
    
    // Birthday
    string private bdate;
    
    // Contact Info
    string private email;
    string private phone;
    string private zip;
    string private city;
    
    // Encryption Key
    string private encryption_key;

    /////////////// STRUCTS ///////////////////
    struct medical_record {
        bool is_uid_generated;
        uint256 record_id;
        string record_msg;
        uint record_status; // 0-Created, 1-Deleted, 2-Changed, 3-Queried, 4-Printed, 5-Copied
        string record_details;
        address patient_address;
        uint record_time;
        address doctor;
        uint doctor_time;
        address audit;
        uint audit_time;
    }

    /////////////// MAPPINGS ///////////////////
    // Changed: Now mapping from patient address to unique_id to medical_record
    mapping(address => mapping(uint256 => medical_record)) public patient_records;
    // Track all unique IDs per patient address
    mapping(address => uint256[]) public patient_record_ids;
    mapping(address => bool) public doctors;
    mapping(address => bool) public audits;

    /////////////// MODIFIERS ///////////////////
    constructor(
        string memory _firstName, 
        string memory _lastName, 
        string memory _IID, 
        string memory _bdate, 
        string memory _email, 
        string memory _phone, 
        string memory _zip, 
        string memory _city, 
        string memory _encryption_key
    ) {
        owner = msg.sender;
        firstName = _firstName;
        lastName = _lastName;
        IID = _IID;
        bdate = _bdate;
        email = _email;
        phone = _phone;
        zip = _zip;
        city = _city;
        encryption_key = _encryption_key;
    }

    modifier only_owner() {
        require(owner == msg.sender, "Not the owner");
        _;
    }

    /////////////// EVENTS ///////////////////
    event event_start_visit(uint256 record_unique_id, string record_msg, uint record_status, uint record_time);
    event event_add_doctor(string return_msg, address doctor_address, uint record_time);
    event event_remove_doctor(string return_msg, address doctor_address, uint record_time);
    event event_add_audit(string return_msg, address audit_address, uint record_time);
    event event_remove_audit(string return_msg, address audit_address, uint record_time);
    event event_patient_print(string record_msg, uint record_status, uint record_time);
    event event_patient_delete(string record_msg, uint record_status, uint record_time);
    event event_doctor_delete(string record_msg, uint record_status, uint record_time);
    event event_doctor_print(string record_msg, uint record_status, uint record_time);
    event event_doctor_copy(string record_msg, uint record_status, uint record_time);
    event event_doctor_query(string record_msg, uint record_status, uint record_time);
    event event_doctor_update(string record_msg, uint record_status, uint record_time);

    /////////////// PATIENT FUNCTIONS ///////////////////

    // Modified: Now stores records by patient address
    function start_visit(uint _time, uint256 unique_id) public {
        require(!patient_records[msg.sender][unique_id].is_uid_generated, "Duplicate ID generated, try again");

        patient_records[msg.sender][unique_id] = medical_record({
            is_uid_generated: true,
            record_id: unique_id,
            record_msg: "New Medical Record is created",
            record_status: 0,
            record_details: "Visit initiate",
            patient_address: msg.sender,
            record_time: _time,
            doctor: address(0),
            doctor_time: 0,
            audit: address(0),
            audit_time: 0
        });
        
        // Add the record ID to the patient's list of records
        patient_record_ids[msg.sender].push(unique_id);

        emit event_start_visit(unique_id, "New Medical Record is created", 0, _time);
    }

    function addDoctors(address _doctor_address) public only_owner returns (string memory) {
        doctors[_doctor_address] = true;
        emit event_add_doctor("A doctor is added.", _doctor_address, block.timestamp);
        return "A doctor is added.";
    }

    function removeDoctors(address _doctor_address) public only_owner returns (string memory) {
        doctors[_doctor_address] = false;
        emit event_remove_doctor("A doctor is removed.", _doctor_address, block.timestamp);
        return "A doctor is removed.";
    }

    function addAudit(address _audit_address) public only_owner returns (string memory) {
        audits[_audit_address] = true;
        emit event_add_audit("An audit is added.", _audit_address, block.timestamp);
        return "An audit is added.";
    }

    function removeAudit(address _audit_address) public only_owner returns (string memory) {
        audits[_audit_address] = false;
        emit event_remove_audit("An audit is removed.", _audit_address, block.timestamp);
        return "An audit is removed.";
    }

    /////////////// RECORD RETRIEVAL ///////////////////

    // New function: Get a specific record by unique_id
    function get_record_detail(uint256 _unique_id) view public returns (medical_record memory) {
        return patient_records[msg.sender][_unique_id];
    }

    // New function: Get all records for the caller
    function get_record_details() view public returns (medical_record[] memory) {
        uint256[] memory ids = patient_record_ids[msg.sender];
        medical_record[] memory records = new medical_record[](ids.length);
        
        for (uint i = 0; i < ids.length; i++) {
            records[i] = patient_records[msg.sender][ids[i]];
        }
        
        return records;
    }

    // Get the total number of records for a patient
    function get_record_count() view public returns (uint256) {
        return patient_record_ids[msg.sender].length;
    }

    // Get the ID at a specific index
    function get_record_id_at_index(uint256 index) view public returns (uint256) {
        require(index < patient_record_ids[msg.sender].length, "Index out of bounds");
        return patient_record_ids[msg.sender][index];
    }

    /////////////// MODIFICATIONS BY PATIENT ///////////////////

    function delete_record(uint256 _unique_id) public returns (string memory) {
        require(patient_records[msg.sender][_unique_id].is_uid_generated, "Record does not exist");
        require(patient_records[msg.sender][_unique_id].patient_address == msg.sender, "Not the patient");
        require(patient_records[msg.sender][_unique_id].record_status != 1, "Record already deleted");

        patient_records[msg.sender][_unique_id].record_details = "";
        patient_records[msg.sender][_unique_id].record_status = 1;
        patient_records[msg.sender][_unique_id].record_time = block.timestamp;
        patient_records[msg.sender][_unique_id].record_msg = "Record is deleted by patient.";

        emit event_patient_delete("Record is deleted by patient.", 1, block.timestamp);
        return "Record is deleted by patient.";
    }

    function print_record(uint256 _unique_id) public returns (string memory) {
        require(patient_records[msg.sender][_unique_id].is_uid_generated, "Record does not exist");
        require(patient_records[msg.sender][_unique_id].patient_address == msg.sender, "Not the patient");
        require(patient_records[msg.sender][_unique_id].record_status != 1, "Record was deleted");

        patient_records[msg.sender][_unique_id].record_status = 4;
        patient_records[msg.sender][_unique_id].record_time = block.timestamp;
        patient_records[msg.sender][_unique_id].record_msg = "Record is printed by patient.";

        emit event_patient_print("Record is printed by patient.", 4, block.timestamp);
        return "Record is printed by patient.";
    }

    /////////////// MODIFICATIONS BY DOCTOR ///////////////////

    function doctor_delete_record(uint256 _unique_id, address patient_address) public returns (string memory) {
        require(patient_records[patient_address][_unique_id].is_uid_generated, "Record does not exist");
        require(doctors[msg.sender], "Not authorized as doctor");
        require(patient_records[patient_address][_unique_id].record_status != 1, "Record already deleted");

        patient_records[patient_address][_unique_id].record_details = "";
        patient_records[patient_address][_unique_id].record_status = 1;
        patient_records[patient_address][_unique_id].doctor = msg.sender;
        patient_records[patient_address][_unique_id].doctor_time = block.timestamp;
        patient_records[patient_address][_unique_id].record_msg = "Record is deleted by doctor.";

        emit event_doctor_delete("Record is deleted by doctor.", 1, block.timestamp);
        return "Record is deleted by doctor.";
    }

    function doctor_print_record(uint256 _unique_id, address patient_address) public returns (string memory) {
        require(patient_records[patient_address][_unique_id].is_uid_generated, "Record does not exist");
        require(doctors[msg.sender], "Not authorized as doctor");
        require(patient_records[patient_address][_unique_id].record_status != 1, "Record was deleted");

        patient_records[patient_address][_unique_id].record_status = 4;
        patient_records[patient_address][_unique_id].doctor = msg.sender;
        patient_records[patient_address][_unique_id].doctor_time = block.timestamp;
        patient_records[patient_address][_unique_id].record_msg = "Record is printed by doctor.";

        emit event_doctor_print("Record is printed by doctor.", 4, block.timestamp);
        return "Record is printed by doctor.";
    }

    function doctor_query_record(uint256 _unique_id, address patient_address) public returns (string memory) {
        require(patient_records[patient_address][_unique_id].is_uid_generated, "Record does not exist");
        require(doctors[msg.sender], "Not authorized as doctor");
        require(patient_records[patient_address][_unique_id].record_status != 1, "Record was deleted");

        patient_records[patient_address][_unique_id].record_status = 3;
        patient_records[patient_address][_unique_id].doctor = msg.sender;
        patient_records[patient_address][_unique_id].doctor_time = block.timestamp;
        patient_records[patient_address][_unique_id].record_msg = "Record is queried by doctor.";

        emit event_doctor_query("Record is queried by doctor.", 3, block.timestamp);
        return "Record is queried by doctor.";
    }

    function doctor_copy_record(uint256 _unique_id, address patient_address) public returns (string memory) {
        require(patient_records[patient_address][_unique_id].is_uid_generated, "Record does not exist");
        require(doctors[msg.sender] || audits[msg.sender], "Not authorized as doctor or audit");
        require(patient_records[patient_address][_unique_id].record_status != 1, "Record was deleted");

        patient_records[patient_address][_unique_id].record_status = 5;
        patient_records[patient_address][_unique_id].doctor = msg.sender;
        patient_records[patient_address][_unique_id].doctor_time = block.timestamp;
        patient_records[patient_address][_unique_id].record_msg = "Record is copied by doctor/audit.";

        emit event_doctor_copy("Record is copied by doctor/audit.", 5, block.timestamp);
        return "Record is copied by doctor/audit.";
    }

    function doctor_update_record(uint256 _unique_id, string memory _update, address patient_address) public returns (string memory) {
        require(patient_records[patient_address][_unique_id].is_uid_generated, "Record does not exist");
        require(doctors[msg.sender], "Not authorized as doctor");
        require(patient_records[patient_address][_unique_id].record_status != 1, "Record was deleted");

        patient_records[patient_address][_unique_id].record_status = 2;
        patient_records[patient_address][_unique_id].doctor = msg.sender;
        patient_records[patient_address][_unique_id].doctor_time = block.timestamp;
        patient_records[patient_address][_unique_id].record_details = _update;
        patient_records[patient_address][_unique_id].record_msg = "Record is updated by doctor.";

        emit event_doctor_update("Record is updated by doctor.", 2, block.timestamp);
        return "Record is updated by doctor.";
    }

    function sample () public returns (string memory) {
        return "Hello World";
    }
}