// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

/**
 * @title MedicalRecord
 * @dev A simple smart contract to store and retrieve medical record metadata.
 * The actual medical files are stored on IPFS, and this contract only stores
 * the IPFS CID (Content ID) along with other metadata.
 */
contract MedicalRecord {

    // A struct to hold the details of a single prescription.
    struct Prescription {
        string doctorName;
        string disease;
        string cid; // The IPFS Content ID for the prescription file/data
        uint256 timestamp;
    }

    // A mapping from a patient's ID to an array of their prescriptions.
    // The key is a string to be flexible (e.g., "patient-12345").
    mapping(string => Prescription[]) public records;

    /**
     * @dev Adds a new prescription record for a given patient.
     * This is a "write" operation and will cost gas to execute.
     * @param _patientId The unique identifier for the patient.
     * @param _doctorName The name of the doctor who issued the prescription.
     * @param _disease The diagnosed disease or condition.
     * @param _cid The IPFS Content ID of the prescription document.
     * @param _timestamp The time the prescription was added.
     */
    function addPrescription(
        string memory _patientId,
        string memory _doctorName,
        string memory _disease,
        string memory _cid,
        uint256 _timestamp
    ) public {
        // Create a new Prescription object in memory
        Prescription memory newPrescription = Prescription({
            doctorName: _doctorName,
            disease: _disease,
            cid: _cid,
            timestamp: _timestamp
        });

        // Push the new prescription to the patient's record array
        records[_patientId].push(newPrescription);
    }

    /**
     * @dev Retrieves the entire medical history for a given patient.
     * This is a "view" (read-only) function, so it does not cost any gas to call.
     * @param _patientId The unique identifier for the patient.
     * @return A dynamic array of the patient's Prescription structs.
     */
    function getHistory(string memory _patientId) public view returns (Prescription[] memory) {
        return records[_patientId];
    }
}
