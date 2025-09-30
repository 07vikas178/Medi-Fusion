// --- DEPENDENCIES ---
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');
const { create } = require('ipfs-http-client');
const Web3 = require('web3');
const multer = require('multer');
const fs = require('fs');
require('dotenv').config(); // For sensitive data like JWT secret

// --- INITIALIZATIONS ---
const app = express();
// Use a strong, secret key for JWT. It's best to store this in a .env file.
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-that-is-long-and-random';

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Serve all frontend HTML/CSS/JS files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));


// --- DATABASE CONNECTION POOL ---
// Connects to your MySQL database.
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
// This configuration connects to your local nodes.
const ipfs = create({ host: 'localhost', port: '5001', protocol: 'http' });
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


// --- FILE UPLOAD SETUP ---
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
const upload = multer({ dest: uploadDir });


// --- AUTHENTICATION MIDDLEWARE ---
// This function acts as a gatekeeper for secure routes.
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format is "Bearer TOKEN"

    if (token == null) return res.sendStatus(401); // 401 Unauthorized - No token provided

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // 403 Forbidden - Token is invalid
        req.user = user; // Attach user payload (e.g., {id, name}) to the request
        next(); // Proceed to the protected route
    });
};


// ================== //
// === API ROUTES === //
// ================== //

// --- PUBLIC ROUTE: DOCTOR LOGIN ---
app.post('/api/doctor/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        // CORRECTED: Queries the `doctor` table as per your hospital_db.sql file
        const [rows] = await db.query('SELECT * FROM doctor WHERE email = ?', [email]);
        const doctor = rows[0];

        if (!doctor) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Compare the provided password with the hashed password in the database
        const isMatch = await bcrypt.compare(password, doctor.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // If credentials are correct, create a JWT token
        // CORRECTED: Uses `doctor_id` from the `doctor` table
        const payload = { id: doctor.doctor_id, name: doctor.name, type: 'doctor' };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }); // Token expires in 1 hour

        res.json({ token });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


// --- SECURE ROUTES (Require a valid token) ---

// Fetches appointments for the logged-in doctor
app.get('/api/my-appointments', authenticateToken, async (req, res) => {
    try {
        const doctorId = req.user.id; // Get doctor ID from the token
        // CORRECTED: Query joins and column names updated to match your hospital_db.sql file exactly.
        const [appointments] = await db.query(`
            SELECT a.consulting_id, a.appointment_time, p.patient_id, p.name AS patient_name, p.gender, p.contact_number
            FROM appointment a
            JOIN patient p ON a.patient_id = p.patient_id
            WHERE a.doctor_id = ? AND a.status = 'Approved'
            ORDER BY a.appointment_time ASC`, [doctorId]
        );
        res.json(appointments);
    } catch (error) {
        console.error("Error fetching appointments:", error);
        res.status(500).json({ error: 'Failed to fetch appointments.' });
    }
});

// Adds a new prescription to IPFS and the blockchain
app.post('/api/prescription', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        let prescriptionData;
        if (req.file) {
            prescriptionData = fs.readFileSync(req.file.path);
            fs.unlinkSync(req.file.path);
        } else if (req.body.text) {
            prescriptionData = Buffer.from(req.body.text);
        } else {
            return res.status(400).json({ error: "No prescription data provided" });
        }

        const ipfsResult = await ipfs.add(prescriptionData);
        const cid = ipfsResult.cid.toString();
        
        const { patientId, doctorName, disease } = req.body;
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

// Retrieves a patient's entire medical history from the blockchain
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
                // Attempt to decode as text, fallback for binary data like PDFs
                data = buffer.toString('utf8').length > 0 ? buffer.toString('utf8') : `[Binary File - CID: ${rec.cid}]`;
            } catch (err) {
                data = '[Error: Content not found on IPFS]';
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


// --- ROOT ROUTE ---
// Redirects the base URL to the main index.html page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


// --- SERVER STARTUP ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running. Open http://localhost:${PORT} in your browser.`);
});

