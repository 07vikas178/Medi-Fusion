// --- DEPENDENCIES ---
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const cors = require('cors'); // Added for frontend communication
const { Web3 } = require('web3'); // Added for Blockchain
require('dotenv').config();

// --- INITIALIZATIONS ---
const app = express();

// --- MIDDLEWARE ---
app.use(cors()); // Use CORS
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
let ipfs; // IPFS client will be initialized asynchronously
const web3 = new Web3('http://127.0.0.1:7545'); // URL from Ganache

// ▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼
// TODO: Fill these in with the details from your blockchain deployment steps.
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
const contractAddress = '0x1Ff7bFf6FbE7179cCeE899d6f0Af628E82992319';
const senderAddress = '0xf624E3dc2138a4c7F6d8DC08140732F676830FeF';
const privateKey = '0xc820d8dd7d7df8e085943965e098a78450ee7823e473f25bac9eb3a572d2614f';
// ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

const contract = new web3.eth.Contract(contractABI, contractAddress);


// --- FILE UPLOAD & JWT SETUP ---
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
const upload = multer({ dest: uploadDir }); // Simplified for single file processing
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

// --- AUTH ROUTES (Patient, Doctor, Hospital) ---
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
        // The verification_status will default to 'Pending' because of the database schema change
        const [result] = await db.query( 'INSERT INTO doctor (name, email, password, contact_number, specialization, availability_status, hospital_name) VALUES (?, ?, ?, ?, ?, ?, ?)', [name, email, hashedPassword, contact_number, specialization, availability_status, hospital_name] );
        res.status(201).json({ message: 'Doctor registered successfully! Your registration is pending approval from the hospital.', doctorId: result.insertId });
    } catch (error) { res.status(500).json({ error: 'Database error during doctor registration.' }); }
});
// [UPDATED] Doctor login now checks for verification status
app.post('/api/doctor/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const [rows] = await db.query('SELECT * FROM doctor WHERE email = ?', [email]);
        if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
        
        const doctor = rows[0];
        const isMatch = await bcrypt.compare(password, doctor.password);
        if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

        // --- NEW: Verification Check ---
        if (doctor.verification_status === 'Pending') {
            return res.status(403).json({ error: 'Your account is pending approval by the hospital.' });
        }
        if (doctor.verification_status === 'Rejected') {
            return res.status(403).json({ error: 'Your registration has been rejected. Please contact the hospital.' });
        }
        // --- End of Verification Check ---

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

// --- NEW: DOCTOR MANAGEMENT ROUTES (FOR HOSPITAL) ---
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
        const { status } = req.body; // Expecting 'Approved' or 'Rejected'
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
// --- END OF NEW ROUTES ---

app.get('/api/my-appointments', authenticateToken, async (req, res) => {
    if (req.user.type !== 'doctor') return res.status(403).json({ error: 'Forbidden' });
    try {
        const doctorId = req.user.id;
        const [appointments] = await db.query(`SELECT a.appointment_id, a.consulting_id, a.appointment_time, p.patient_id, p.name AS patient_name, p.gender, p.contact_number FROM appointment a JOIN patient p ON a.patient_id = p.patient_id WHERE a.doctor_id = ? AND a.status = 'Approved' ORDER BY a.appointment_time ASC`, [doctorId]);
        res.json(appointments);
    } catch (error) { res.status(500).json({ error: 'Failed to fetch your appointments.' }); }
});


// --- DECENTRALIZED MEDICAL RECORD ROUTES (IPFS & BLOCKCHAIN) ---
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
        
        const txData = contract.methods.addPrescription(String(patientId), doctorName, disease, cid, timestamp).encodeABI();
        
        const tx = { from: senderAddress, to: contractAddress, gas: 3000000, data: txData };
        const signed = await web3.eth.accounts.signTransaction(tx, privateKey);
        const receipt = await web3.eth.sendSignedTransaction(signed.rawTransaction);
        
        res.json({ success: true, cid: cid, transactionHash: receipt.transactionHash });
    } catch (e) {
        console.error("API Error in /api/prescription:", e);
        res.status(500).json({ error: e.message });
    }
});
app.get('/api/history/:patientId', authenticateToken, async (req, res) => {
     try {
        const patientId = req.params.patientId;
        const records = await contract.methods.getHistory(patientId).call({ from: senderAddress });

        if (!records || records.length === 0) return res.json({ history: [] });

        const results = await Promise.all(records.map(async rec => {
            let data = '';
            try {
                const chunks = [];
                for await (const chunk of ipfs.cat(rec.cid)) {
                    chunks.push(chunk);
                }
                const buffer = Buffer.concat(chunks);
                data = buffer.toString('utf8');
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