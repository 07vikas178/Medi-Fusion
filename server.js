// --- DEPENDENCIES ---
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const cors = require('cors'); 
const { Web3 } = require('web3');
require('dotenv').config();

// --- INITIALIZATIONS ---
const app = express();

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// --- DATABASE CONNECTION ---
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'hospital_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
}).promise();

// --- IPFS & BLOCKCHAIN SETUP ---
let ipfs;
const web3 = new Web3('http://127.0.0.1:7545'); 

// ▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼
// TODO: IMPORTANT! Update these details after you re-deploy the new smart contract.
const contractABI = [
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "_patientId",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "_doctorName",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "_disease",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "_cid",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "_timestamp",
				"type": "uint256"
			}
		],
		"name": "addPrescription",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"name": "consentLog",
		"outputs": [
			{
				"internalType": "string",
				"name": "granteeId",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "accessLevel",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "duration",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "status",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "_patientId",
				"type": "string"
			}
		],
		"name": "getConsentLog",
		"outputs": [
			{
				"components": [
					{
						"internalType": "string",
						"name": "granteeId",
						"type": "string"
					},
					{
						"internalType": "string",
						"name": "accessLevel",
						"type": "string"
					},
					{
						"internalType": "uint256",
						"name": "duration",
						"type": "uint256"
					},
					{
						"internalType": "string",
						"name": "status",
						"type": "string"
					},
					{
						"internalType": "uint256",
						"name": "timestamp",
						"type": "uint256"
					}
				],
				"internalType": "struct MedicalRecord.Consent[]",
				"name": "",
				"type": "tuple[]"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "_patientId",
				"type": "string"
			}
		],
		"name": "getHistory",
		"outputs": [
			{
				"components": [
					{
						"internalType": "string",
						"name": "doctorName",
						"type": "string"
					},
					{
						"internalType": "string",
						"name": "disease",
						"type": "string"
					},
					{
						"internalType": "string",
						"name": "cid",
						"type": "string"
					},
					{
						"internalType": "uint256",
						"name": "timestamp",
						"type": "uint256"
					}
				],
				"internalType": "struct MedicalRecord.Prescription[]",
				"name": "",
				"type": "tuple[]"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "_patientId",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "_granteeId",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "_accessLevel",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "_duration",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "_status",
				"type": "string"
			}
		],
		"name": "manageConsent",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"name": "records",
		"outputs": [
			{
				"internalType": "string",
				"name": "doctorName",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "disease",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "cid",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
];
const contractAddress = '0xA8bF3F883D60D45Ee0cD9B1566E4DFa36104BBf3'; // The new address after deployment
const senderAddress = '0x68a04fd4E12e1f111b1E276C9A12fF39Ae6D6B42';
const privateKey = '0xceeaa6cd7eef19c4880963f57086379e685d4a8853b3574f7632e43c3f69453c';
// ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

const contract = new web3.eth.Contract(contractABI, contractAddress);

// --- FILE UPLOAD & JWT SETUP ---
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
const upload = multer({ dest: uploadDir });
const JWT_SECRET = process.env.JWT_SECRET || 'a-very-secure-secret-key-for-jwt';

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// ======================= //
// === FRONTEND ROUTES === //
// ======================= //
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ================== //
// === API ROUTES === //
// ================== //

// --- AUTH ROUTES ---
app.post('/api/patient/register', async (req, res) => {
    try {
        const { name, email, password, contact_number, address, gender, dob } = req.body;
        const [existing] = await db.query('SELECT email FROM patient WHERE email = ?', [email]);
        if (existing.length > 0) return res.status(409).json({ error: 'An account with this email already exists.' });
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await db.query( 'INSERT INTO patient (name, email, password, contact_number, address, gender, dob) VALUES (?, ?, ?, ?, ?, ?, ?)', [name, email, hashedPassword, contact_number, address, gender, dob] );
        res.status(201).json({ message: 'Patient registered successfully!', patientId: result.insertId });
    } catch (error) { res.status(500).json({ error: 'Database error during registration.' }); }
});
app.post('/api/patient/login', async (req, res) => {
    try {
        const { name, password } = req.body;
        const [rows] = await db.query('SELECT * FROM patient WHERE name = ?', [name]);
        if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
        const patient = rows[0];
        const isMatch = await bcrypt.compare(password, patient.password);
        if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });
        const token = jwt.sign({ id: patient.patient_id, type: 'patient', name: patient.name }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) { res.status(500).json({ error: 'Server error during login.' }); }
});
app.post('/api/doctor/register', async (req, res) => {
    try {
        const { name, email, password, contact_number, specialization, availability_status, hospital_name } = req.body;
        const [existing] = await db.query('SELECT email FROM doctor WHERE email = ?', [email]);
        if (existing.length > 0) return res.status(409).json({ error: 'A doctor with this email already exists.' });
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await db.query( 'INSERT INTO doctor (name, email, password, contact_number, specialization, availability_status, hospital_name) VALUES (?, ?, ?, ?, ?, ?, ?)', [name, email, hashedPassword, contact_number, specialization, availability_status, hospital_name] );
        res.status(201).json({ message: 'Doctor registered successfully! Your registration is pending approval from the hospital.', doctorId: result.insertId });
    } catch (error) { res.status(500).json({ error: 'Database error during doctor registration.' }); }
});
app.post('/api/doctor/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const [rows] = await db.query('SELECT * FROM doctor WHERE email = ?', [email]);
        if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
        
        const doctor = rows[0];
        const isMatch = await bcrypt.compare(password, doctor.password);
        if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

        if (doctor.verification_status === 'Pending') {
            return res.status(403).json({ error: 'Your account is pending approval by the hospital.' });
        }
        if (doctor.verification_status === 'Rejected') {
            return res.status(403).json({ error: 'Your registration has been rejected. Please contact the hospital.' });
        }

        const token = jwt.sign({ id: doctor.doctor_id, type: 'doctor', name: doctor.name, hospital_name: doctor.hospital_name }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) { res.status(500).json({ error: 'Server error during login.' }); }
});
app.post('/api/hospital/register', async (req, res) => {
    try {
        const { hospital_name, email, password, phone, address, num_beds, specialties } = req.body;
        const [existing] = await db.query('SELECT email FROM hospitals WHERE email = ?', [email]);
        if (existing.length > 0) return res.status(409).json({ error: 'A hospital with this email already exists.' });
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await db.query( 'INSERT INTO hospitals (hospital_name, email, password, phone, address, num_beds, specialties) VALUES (?, ?, ?, ?, ?, ?, ?)', [hospital_name, email, hashedPassword, phone, address, num_beds, specialties] );
        res.status(201).json({ message: 'Hospital registered successfully!', hospitalId: result.insertId });
    } catch (error) { res.status(500).json({ error: 'Database error during hospital registration.' }); }
});
app.post('/api/hospital/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const [rows] = await db.query('SELECT * FROM hospitals WHERE email = ?', [email]);
        if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
        const hospital = rows[0];
        const isMatch = await bcrypt.compare(password, hospital.password);
        if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });
        const token = jwt.sign({ id: hospital.id, type: 'hospital', name: hospital.hospital_name }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) { res.status(500).json({ error: 'Server error during login.' }); }
});

// --- APPOINTMENT WORKFLOW ROUTES ---
app.get('/api/hospitals', authenticateToken, async (req, res) => {
    try {
        const [hospitals] = await db.query("SELECT id, hospital_name FROM hospitals ORDER BY hospital_name ASC");
        res.json(hospitals);
    } catch (error) {
        console.error('Failed to fetch hospitals:', error);
        res.status(500).json({ error: 'Failed to fetch hospitals.' });
    }
});
app.get('/api/available-doctors', authenticateToken, async (req, res) => {
    try {
        const { hospital } = req.query; 
        if (!hospital) {
            return res.status(400).json({ error: 'Hospital name is required.' });
        }
        const [doctors] = await db.query("SELECT doctor_id, name, specialization FROM doctor WHERE availability_status = 'Available' AND hospital_name = ?", [hospital]);
        res.json(doctors);
    } catch (error) { 
        console.error('Failed to fetch available doctors:', error);
        res.status(500).json({ error: 'Failed to fetch available doctors.' }); 
    }
});
app.get('/api/doctor-details/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const [doctor] = await db.query("SELECT name, specialization FROM doctor WHERE doctor_id = ?", [id]);
        if (doctor.length === 0) {
            return res.status(404).json({ error: 'Doctor not found.' });
        }
        res.json(doctor[0]);
    } catch (error) {
        console.error('Failed to fetch doctor details:', error);
        res.status(500).json({ error: 'Failed to fetch doctor details.' });
    }
});
app.post('/api/appointments', authenticateToken, async (req, res) => {
    if (req.user.type !== 'patient') return res.status(403).json({ error: 'Forbidden' });
    try {
        const { doctor_id, appointment_time } = req.body;
        const patient_id = req.user.id;
        const consulting_id = crypto.randomBytes(4).toString('hex').toUpperCase();
        await db.query("INSERT INTO appointment (consulting_id, patient_id, doctor_id, appointment_time, status) VALUES (?, ?, ?, ?, 'Pending')", [consulting_id, patient_id, doctor_id, appointment_time]);
        res.status(201).json({ message: 'Appointment booked successfully! Awaiting hospital approval.', consulting_id });
    } catch (error) { res.status(500).json({ error: 'Failed to book appointment' }); }
});
app.get('/api/my-patient-appointments', authenticateToken, async (req, res) => {
    if (req.user.type !== 'patient') return res.status(403).json({ error: 'Forbidden' });
    try {
        const [appointments] = await db.query(`SELECT a.appointment_id, a.appointment_time, a.status, d.name as doctor_name FROM appointment a JOIN doctor d ON a.doctor_id = d.doctor_id WHERE a.patient_id = ? ORDER BY a.appointment_time DESC`, [req.user.id]);
        res.json(appointments);
    } catch (error) { res.status(500).json({ error: 'Failed to fetch your appointments' }); }
});
app.get('/api/all-appointments', authenticateToken, async (req, res) => {
    if (req.user.type !== 'hospital') return res.status(403).json({ error: 'Forbidden' });
    try {
        const hospitalName = req.user.name; 
        const [appointments] = await db.query(`SELECT a.*, p.name AS patient_name, d.name AS doctor_name FROM appointment a JOIN patient p ON a.patient_id = p.patient_id JOIN doctor d ON a.doctor_id = d.doctor_id WHERE d.hospital_name = ? ORDER BY a.appointment_time DESC`, [hospitalName]);
        res.json(appointments);
    } catch (error) { res.status(500).json({ error: 'Failed to fetch appointments.' }); }
});
app.put('/api/appointments/:id/status', authenticateToken, async (req, res) => {
    if (req.user.type !== 'hospital') return res.status(403).json({ error: 'Forbidden' });
    try {
        const { status } = req.body;
        const { id } = req.params;
        await db.query('UPDATE appointment SET status = ? WHERE appointment_id = ?', [status, id]);
        res.json({ message: `Appointment ${id} has been ${status}.` });
    } catch (error) { res.status(500).json({ error: 'Failed to update appointment status.' }); }
});

// --- DOCTOR MANAGEMENT ROUTES (FOR HOSPITAL) ---
app.get('/api/pending-doctors', authenticateToken, async (req, res) => {
    if (req.user.type !== 'hospital') return res.status(403).json({ error: 'Forbidden' });
    try {
        const hospitalName = req.user.name;
        const [doctors] = await db.query(
            "SELECT doctor_id, name, specialization, email, contact_number FROM doctor WHERE hospital_name = ? AND verification_status = 'Pending'",
            [hospitalName]
        );
        res.json(doctors);
    } catch (error) {
        console.error('Failed to fetch pending doctors:', error);
        res.status(500).json({ error: 'Failed to fetch doctor requests.' });
    }
});
app.put('/api/doctors/:id/status', authenticateToken, async (req, res) => {
    if (req.user.type !== 'hospital') return res.status(403).json({ error: 'Forbidden' });
    try {
        const { status } = req.body; 
        const { id } = req.params;
        if (status !== 'Approved' && status !== 'Rejected') {
            return res.status(400).json({ error: 'Invalid status provided.' });
        }
        await db.query('UPDATE doctor SET verification_status = ? WHERE doctor_id = ?', [status, id]);
        res.json({ message: `Doctor has been ${status}.` });
    } catch (error) {
        console.error('Failed to update doctor status:', error);
        res.status(500).json({ error: 'Failed to update doctor status.' });
    }
});
app.get('/api/my-appointments', authenticateToken, async (req, res) => {
    if (req.user.type !== 'doctor') return res.status(403).json({ error: 'Forbidden' });
    try {
        const doctorId = req.user.id;
        const [appointments] = await db.query(`SELECT a.appointment_id, a.consulting_id, a.appointment_time, p.patient_id, p.name AS patient_name, p.gender, p.contact_number FROM appointment a JOIN patient p ON a.patient_id = p.patient_id WHERE a.doctor_id = ? AND a.status = 'Approved' ORDER BY a.appointment_time ASC`, [doctorId]);
        res.json(appointments);
    } catch (error) { res.status(500).json({ error: 'Failed to fetch your appointments.' }); }
});

// --- DECENTRALIZED MEDICAL RECORD & CONSENT ROUTES ---

// --- [NEW] Patient Prescription Route ---
app.get('/api/my-prescriptions', authenticateToken, async (req, res) => {
    if (req.user.type !== 'patient') return res.status(403).json({ error: 'Forbidden' });
    try {
        const patientId = req.user.id.toString();
        const records = await contract.methods.getHistory(patientId).call({ from: senderAddress });
        if (!records || records.length === 0) {
            return res.json([]); // Return empty array if no records
        }
        const results = await Promise.all(records.map(async rec => {
            let data = '';
            try {
                const chunks = [];
                for await (const chunk of ipfs.cat(rec.cid)) { chunks.push(chunk); }
                data = Buffer.concat(chunks).toString('utf8');
            } catch (err) {
                console.error(`IPFS fetch error for CID ${rec.cid}:`, err);
                data = '[Error: Could not retrieve prescription content from IPFS.]';
            }
            return {
                doctorName: rec.doctorName,
                disease: rec.disease,
                timestamp: rec.timestamp.toString(),
                data: data,
            };
        }));
        res.json(results.reverse()); // Show most recent first
    } catch (e) {
        console.error("API Error in /api/my-prescriptions:", e);
        res.status(500).json({ error: e.message });
    }
});

// --- Prescription Route ---
app.post('/api/prescription', authenticateToken, upload.single('file'), async (req, res) => {
    if (req.user.type !== 'doctor') return res.status(403).json({ error: 'Forbidden' });
    try {
        let prescriptionData;
        if (req.file) {
            prescriptionData = fs.readFileSync(req.file.path);
            fs.unlinkSync(req.file.path);
        } else if (req.body.text) {
            prescriptionData = Buffer.from(req.body.text);
        } else {
            return res.status(400).json({ error: "No prescription data (text or file) provided" });
        }
        const ipfsResult = await ipfs.add(prescriptionData);
        const cid = ipfsResult.cid.toString();
        const { patientId, disease } = req.body;
        const doctorName = req.user.name;
        const timestamp = Date.now();
        const prescriptionMethod = contract.methods.addPrescription(String(patientId), doctorName, disease, cid, timestamp);
        const estimatedGas = await prescriptionMethod.estimateGas({ from: senderAddress });
        const gasPrice = await web3.eth.getGasPrice();
        const tx = {
            from: senderAddress,
            to: contractAddress,
            gas: estimatedGas,
            gasPrice: gasPrice,
            data: prescriptionMethod.encodeABI()
        };
        const signed = await web3.eth.accounts.signTransaction(tx, privateKey);
        const receipt = await web3.eth.sendSignedTransaction(signed.rawTransaction);
        res.json({ success: true, cid: cid, transactionHash: receipt.transactionHash });
    } catch (e) { 
        console.error("API Error in /api/prescription:", e);
        res.status(500).json({ error: e.message }); 
    }
});

// --- Consent Management Routes ---
app.post('/api/consent', authenticateToken, async (req, res) => {
    if (req.user.type !== 'patient') return res.status(403).json({ error: 'Forbidden' });
    try {
        const { granteeId, accessLevel, duration, status } = req.body;
        const patientId = req.user.id.toString();
        const consentMethod = contract.methods.manageConsent(patientId, granteeId, accessLevel, duration, status);
        const estimatedGas = await consentMethod.estimateGas({ from: senderAddress });
        const gasPrice = await web3.eth.getGasPrice();
        const tx = {
            from: senderAddress,
            to: contractAddress,
            gas: estimatedGas,
            gasPrice: gasPrice,
            data: consentMethod.encodeABI()
        };
        const signed = await web3.eth.accounts.signTransaction(tx, privateKey);
        const receipt = await web3.eth.sendSignedTransaction(signed.rawTransaction);
        res.json({ success: true, message: `Consent status set to ${status}.`, transactionHash: receipt.transactionHash });
    } catch(e) {
        console.error("API Error in /api/consent:", e);
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/consent-log', authenticateToken, async (req, res) => {
    if (req.user.type !== 'patient') return res.status(403).json({ error: 'Forbidden' });
    try {
        const patientId = req.user.id.toString();
        const log = await contract.methods.getConsentLog(patientId).call({ from: senderAddress });
        if (!log) {
            return res.json({ log: [] });
        }
        
        const serializableLog = log.map(entry => {
            return {
                granteeId: entry.granteeId,
                accessLevel: entry.accessLevel,
                duration: entry.duration.toString(),
                status: entry.status,
                timestamp: entry.timestamp.toString()
            };
        });
        res.json({ log: serializableLog });
    } catch(e) {
        console.error("API Error in /api/consent-log:", e);
        res.status(500).json({ error: e.message });
    }
});


// --- Medical History Route with Consent Check ---
app.get('/api/history/:patientId', authenticateToken, async (req, res) => {
    if (req.user.type !== 'doctor') return res.status(403).json({ error: 'Forbidden: Only doctors can view patient history.' });
    
    try {
        const patientId = req.params.patientId;
        const requesterId = req.user.id.toString(); 
        
        const consentLog = await contract.methods.getConsentLog(patientId).call({ from: senderAddress });
        
        let hasValidConsent = false;
        if (consentLog) {
            for (let i = consentLog.length - 1; i >= 0; i--) {
                const consent = consentLog[i];
                if (consent.granteeId === requesterId) {
                    if (consent.status === 'Granted') {
                        const consentTimestamp = parseInt(consent.timestamp.toString());
                        const duration = parseInt(consent.duration.toString());
                        const nowInSeconds = Math.floor(Date.now() / 1000);
                        if ((consentTimestamp + duration) > nowInSeconds) {
                            hasValidConsent = true;
                        }
                    }
                    break;
                }
            }
        }
        
        if (!hasValidConsent) {
            return res.status(403).json({ error: 'Access Denied. Patient consent is required or has expired.' });
        }
        
        const records = await contract.methods.getHistory(patientId).call({ from: senderAddress });
        if (!records || records.length === 0) return res.json({ history: [] });

        const results = await Promise.all(records.map(async rec => {
            let data = '';
            try {
                const chunks = [];
                for await (const chunk of ipfs.cat(rec.cid)) { chunks.push(chunk); }
                data = Buffer.concat(chunks).toString('utf8');
            } catch (err) {
                data = '[Error: Content not found on IPFS or content is a file]';
            }
            return {
                doctorName: rec.doctorName, disease: rec.disease, cid: rec.cid,
                timestamp: rec.timestamp.toString(), data,
            };
        }));
        res.json({ history: results });
    } catch (e) {
        console.error("API Error in /api/history:", e);
        res.status(500).json({ error: e.message });
    }
});


// ====================== //
// === SERVER STARTUP === //
// ====================== //
const PORT = process.env.PORT || 3000;

const startServer = async () => {
    try {
        const { create } = await import('ipfs-http-client');
        ipfs = create({ host: 'localhost', port: '5001', protocol: 'http' });
        console.log('IPFS client initialized successfully.');
        app.listen(PORT, () => {
            console.log(`Server is running. Open http://localhost:${PORT} in your browser.`);
        });
    } catch (error) {
        console.error('Failed to start the server:', error);
        process.exit(1);
    }
};

startServer();