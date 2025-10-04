// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

/**
 * @title MedicalRecord
 * @dev A smart contract to store medical record metadata and manage patient consent.
 * The actual medical files are stored on IPFS, and this contract only stores
 * the IPFS CID (Content ID) along with other metadata and consent logs.
 */
contract MedicalRecord {

    // A struct to hold the details of a single prescription.
    struct Prescription {
        string doctorName;
        string disease;
        string cid; // The IPFS Content ID for the prescription file/data
        uint256 timestamp;
    }

    // --- NEW: Struct for Consent Management ---
    /**
     * @dev Holds the details of a single consent action.
     * granteeId: The unique ID of the doctor or institution being granted access.
     * accessLevel: What they can see (e.g., "View Full History").
     * duration: The period in seconds for which access is granted.
     * status: 'Granted' or 'Revoked'.
     * timestamp: When the consent was given or revoked.
    */
    struct Consent {
        string granteeId;
        string accessLevel;
        uint256 duration; 
        string status; 
        uint256 timestamp;
    }

    // A mapping from a patient's ID to an array of their prescriptions.
    mapping(string => Prescription[]) public records;

    // --- NEW: Mapping for Consent Logs ---
    // A mapping from a patient's ID to an array of their consent actions.
    mapping(string => Consent[]) public consentLog;

    /**
     * @dev Adds a new prescription record for a given patient.
     * This is a "write" operation and will cost gas to execute.
     */
    function addPrescription(
        string memory _patientId,
        string memory _doctorName,
        string memory _disease,
        string memory _cid,
        uint256 _timestamp
    ) public {
        records[_patientId].push(Prescription({
            doctorName: _doctorName,
            disease: _disease,
            cid: _cid,
            timestamp: _timestamp
        }));
    }
    
    // --- NEW: Function to Grant or Revoke Consent ---
    /**
     * @dev Adds a new consent entry to the patient's log. Can be used for granting or revoking.
     * This is a "write" operation and will cost gas to execute.
     */
    function manageConsent(
        string memory _patientId,
        string memory _granteeId,
        string memory _accessLevel,
        uint256 _duration,
        string memory _status
    ) public {
        consentLog[_patientId].push(Consent({
            granteeId: _granteeId,
            accessLevel: _accessLevel,
            duration: _duration,
            status: _status, // Should be 'Granted' or 'Revoked'
            timestamp: block.timestamp
        }));
    }

    /**
     * @dev Retrieves the entire medical history for a given patient.
     * This is a "view" function. Access control is handled by the backend.
     */
    function getHistory(string memory _patientId) public view returns (Prescription[] memory) {
        return records[_patientId];
    }

    // --- NEW: Function to retrieve a patient's consent log ---
    /**
     * @dev Retrieves the entire consent history for a given patient.
     * This is a "view" (read-only) function, so it does not cost any gas to call.
     */
    function getConsentLog(string memory _patientId) public view returns (Consent[] memory) {
        return consentLog[_patientId];
    }
}