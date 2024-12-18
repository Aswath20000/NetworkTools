const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const { Socket } = require('net');
const ping = require('ping');
const multer = require('multer');
const fs = require('fs');
const axios = require('axios');
const http = require('http');
const socketIO = require('socket.io');
const cron = require('node-cron');
const FormData = require('form-data');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIO(server, { cors: { origin: '*' } });

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/networkToolData', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('MongoDB Connected'))
  .catch((err) => console.error('MongoDB Connection Error:', err));

// MongoDB Schemas
const PingResult = mongoose.model('PingResult', new mongoose.Schema({
    ipAddress: String,
    alive: Boolean,
    time: String,
    timestamp: { type: Date, default: Date.now },
}));

const PortScan = mongoose.model('PortScan', new mongoose.Schema({
    ipAddress: String,
    openPorts: [Number],
    timestamp: { type: Date, default: Date.now },
}));

const NetworkScan = mongoose.model('NetworkScan', new mongoose.Schema({
    subnet: String,
    activeDevices: [String],
    timestamp: { type: Date, default: Date.now },
}));

const MalwareScan = mongoose.model('MalwareScan', new mongoose.Schema({
    fileName: String,
    result: {
        message: String,
        details: Array,
    },
    timestamp: { type: Date, default: Date.now },
}));

const ScheduledScan = mongoose.model('ScheduledScan', new mongoose.Schema({
    ipAddress: { type: String, required: true },
    portRange: { start: Number, end: Number },
    interval: { type: Number, required: true }, // Interval in minutes
    lastExecuted: { type: Date, default: null },
    createdAt: { type: Date, default: Date.now },
    scanHistory: [
        {
            timestamp: { type: Date, default: Date.now },
            openPorts: [Number],
        },
    ],
}));



// Multer for File Uploads
const upload = multer({
    dest: 'uploads/',
    limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB limit
});

// Port Scan Logic (Reusable)
const portScan = async (ipAddress, portRange) => {
    const openPorts = [];
    const totalPorts = portRange.end - portRange.start + 1;
    let scannedPorts = 0;

    for (let port = portRange.start; port <= portRange.end; port++) {
        await new Promise((resolve) => {
            const socket = new Socket();
            socket.setTimeout(1000);

            socket.on('connect', () => {
                openPorts.push(port);
                scannedPorts++;
                const progress = Math.round((scannedPorts / totalPorts) * 100);
                io.emit('port-scan-progress', { progress });
                socket.destroy();
                resolve();
            });
            socket.on('error', () => {
                scannedPorts++;
                const progress = Math.round((scannedPorts / totalPorts) * 100);
                io.emit('port-scan-progress', { progress });
                resolve();
            });
            socket.on('timeout', () => {
                scannedPorts++;
                const progress = Math.round((scannedPorts / totalPorts) * 100);
                io.emit('port-scan-progress', { progress });
                resolve();
            });

            socket.connect(port, ipAddress);
        });
    }

    return openPorts;
};

// Routes
// 1. Ping IP
app.post('/ping', async (req, res) => {
    const { ipAddress } = req.body;

    if (!ipAddress) return res.status(400).json({ error: 'IP Address is required' });

    try {
        const result = await ping.promise.probe(ipAddress);
        const newResult = new PingResult({ ipAddress, alive: result.alive, time: result.time });
        await newResult.save();
        res.json(newResult);
    } catch (err) {
        res.status(500).json({ error: 'Ping failed', details: err.message });
    }
});

// 2. Port Scan
app.post('/scan-ports', async (req, res) => {
    const { ipAddress, portRange } = req.body;

    if (!ipAddress || !portRange) return res.status(400).json({ error: 'Invalid input' });

    try {
        const openPorts = await portScan(ipAddress, portRange);
        const result = new PortScan({ ipAddress, openPorts });
        await result.save();
        io.emit('port-scan-completed', openPorts);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Port scan failed', details: err.message });
    }
});

// 3. Scheduled Port Scan
app.post('/schedule-port-scan', async (req, res) => {
    const { ipAddress, interval, portRange } = req.body;

    if (!ipAddress || !interval || !portRange || !portRange.start || !portRange.end) {
        return res.status(400).json({ error: 'IP Address, interval, and valid port range are required.' });
    }

    try {
        // Save scheduled scan details in the database
        const scheduledScan = new ScheduledScan({
            ipAddress,
            portRange,
            interval,
            scanHistory: [],
        });
        await scheduledScan.save();

        const cronSchedule = `*/${interval} * * * *`; // Run every 'interval' minutes
        cron.schedule(cronSchedule, async () => {
            console.log(`Scheduled port scan for ${ipAddress} started.`);
            try {
                const openPorts = await portScan(ipAddress, portRange);

                // Add scan results to scanHistory
                const scanData = {
                    timestamp: new Date(),
                    openPorts,
                };
                await ScheduledScan.findByIdAndUpdate(scheduledScan._id, {
                    lastExecuted: new Date(),
                    $push: { scanHistory: scanData },
                });

                console.log(`Scheduled port scan for ${ipAddress} completed. Open ports: ${openPorts}`);

                // Emit scan results to the frontend
                io.emit('scheduled-port-scan-result', { ipAddress, scanData });
            } catch (err) {
                console.error(`Error in scheduled port scan for ${ipAddress}:`, err);
            }
        });

        res.json({
            message: `Port scan scheduled for ${ipAddress} every ${interval} minute(s) for ports ${portRange.start}-${portRange.end}.`,
            scheduleId: scheduledScan._id,
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to schedule port scan.', details: err.message });
    }
});



// 4. File Upload and VirusTotal Scan
app.post('/scan-file', upload.single('file'), async (req, res) => {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;

    if (!apiKey) {
        return res.status(500).json({ error: 'VirusTotal API key is not configured.' });
    }

    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded.' });
    }

    try {
        const filePath = req.file.path;
        const fileSize = fs.statSync(filePath).size;

        if (fileSize > 32 * 1024 * 1024) {
            return res.status(400).json({ error: 'File exceeds VirusTotal size limit.' });
        }

        const formData = new FormData();
        formData.append('file', fs.createReadStream(filePath));
        const headers = {
            'x-apikey': apiKey,
            ...formData.getHeaders(),
        };

        const uploadResponse = await axios.post('https://www.virustotal.com/api/v3/files', formData, { headers });
        const fileId = uploadResponse.data.data.id;

        let retries = 10;
        const delay = 15000;
        let reportResponse;

        while (retries > 0) {
            reportResponse = await axios.get(`https://www.virustotal.com/api/v3/analyses/${fileId}`, {
                headers: { 'x-apikey': apiKey },
            });

            const status = reportResponse?.data?.data?.attributes?.status;
            if (status === 'completed') break;

            await new Promise((resolve) => setTimeout(resolve, delay));
            retries--;
        }

        if (retries === 0) {
            return res.status(500).json({ error: 'Failed to retrieve scan results.' });
        }

        const scanResults = reportResponse.data.data.attributes.results || {};
        const maliciousDetails = Object.entries(scanResults).filter(
            ([engine, result]) => result?.category === 'malicious'
        );

        fs.unlinkSync(filePath);

        const result = new MalwareScan({
            fileName: req.file.originalname,
            result: {
                message: maliciousDetails.length > 0 ? 'Malware detected' : 'No malware detected',
                details: maliciousDetails.map(([engine, result]) => ({
                    engine,
                    verdict: result?.category,
                    description: result?.result,
                })),
            },
        });
        await result.save();

        res.json(result.result);
    } catch (error) {
        res.status(500).json({ error: 'Error during VirusTotal scan', details: error.message });
    }
});

// 5. Network Scan
app.post('/scan-network', async (req, res) => {
    const { subnet } = req.body;

    if (!subnet) {
        return res.status(400).json({ error: 'Subnet is required (e.g., 192.168.1.)' });
    }

    const totalIPs = 20;
    let scannedIPs = 0;
    const activeDevices = [];

    try {
        for (let i = 1; i <= totalIPs; i++) {
            const ipAddress = `${subnet}${i}`;
            const result = await ping.promise.probe(ipAddress, { timeout: 1 });

            if (result.alive) {
                activeDevices.push(ipAddress);
            }

            scannedIPs++;
            const progress = Math.round((scannedIPs / totalIPs) * 100);
            io.emit('network-scan-progress', { progress });
        }

        const networkScanResult = new NetworkScan({ subnet, activeDevices });
        await networkScanResult.save();
        io.emit('network-scan-completed', activeDevices);
        res.json({ subnet, activeDevices });
    } catch (err) {
        res.status(500).json({ error: 'Network scan failed', details: err.message });
    }
});

// Real-time connection
io.on('connection', (socket) => {
    console.log('Client connected to Socket.IO');
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
