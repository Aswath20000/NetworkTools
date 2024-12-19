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
    interval: { type: Number, required: true },
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
    console.log(`Port scan started for IP: ${ipAddress}, Port Range: ${portRange.start}-${portRange.end}`);
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
                console.log(`Port ${port} is open.`);
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
    console.log(`Port scan completed for IP: ${ipAddress}. Open Ports: ${openPorts}`);
    return openPorts;
};

// Routes
// 1. Ping IP
app.post('/ping', async (req, res) => {
    const { ipAddress } = req.body;

    if (!ipAddress) return res.status(400).json({ error: 'IP Address is required' });

    try {
        console.log(`Ping started for IP: ${ipAddress}`);
        const result = await ping.promise.probe(ipAddress);
        const newResult = new PingResult({ ipAddress, alive: result.alive, time: result.time });
        await newResult.save();
        console.log(`Ping completed for IP: ${ipAddress} - Alive: ${result.alive}, Time: ${result.time}`);
        res.json(newResult);
    } catch (err) {
        console.error(`Ping failed for IP: ${ipAddress} - ${err.message}`);
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
        console.log(`Port scan results saved for IP: ${ipAddress}`);
        res.json(result);
    } catch (err) {
        console.error(`Port scan failed for IP: ${ipAddress} - ${err.message}`);
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
        const scheduledScan = new ScheduledScan({
            ipAddress,
            portRange,
            interval,
            scanHistory: [],
        });
        await scheduledScan.save();

        const cronSchedule = `*/${interval} * * * *`;
        cron.schedule(cronSchedule, async () => {
            console.log(`Scheduled port scan triggered for IP: ${ipAddress}`);
            try {
                const openPorts = await portScan(ipAddress, portRange);
                const scanData = { timestamp: new Date(), openPorts };
                await ScheduledScan.findByIdAndUpdate(scheduledScan._id, {
                    lastExecuted: new Date(),
                    $push: { scanHistory: scanData },
                });
                io.emit('scheduled-port-scan-result', { ipAddress, scanData });
                console.log(`Scheduled port scan completed for IP: ${ipAddress}. Open Ports: ${openPorts}`);
            } catch (err) {
                console.error(`Error in scheduled port scan:`, err);
            }
        });

        res.json({
            message: `Port scan scheduled for ${ipAddress} every ${interval} minute(s).`,
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
        console.log(`Malware scan started for file: ${req.file.originalname}`);
        const filePath = req.file.path;
        const fileSize = fs.statSync(filePath).size;

        if (fileSize > 32 * 1024 * 1024) {
            console.error(`File exceeds VirusTotal size limit.`);
            return res.status(400).json({ error: 'File exceeds VirusTotal size limit (32MB).' });
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
            console.error(`Failed to retrieve scan results for file: ${req.file.originalname}`);
            return res.status(500).json({ error: 'Failed to retrieve scan results.' });
        }

        const scanResults = reportResponse.data.data.attributes.results || {};
        const maliciousDetails = Object.entries(scanResults)
            .filter(([engine, result]) => result?.category === 'malicious')
            .map(([engine, result]) => ({
                engine,
                verdict: result?.category,
                description: result?.result,
            }));

        fs.unlinkSync(filePath);

        const result = new MalwareScan({
            fileName: req.file.originalname,
            result: {
                message: maliciousDetails.length > 0 ? 'Malware detected' : 'No malware detected',
                details: maliciousDetails,
            },
        });
        await result.save();

        console.log(`Malware scan completed for file: ${req.file.originalname}. Result: ${result.result.message}`);
        res.json(result.result);
    } catch (error) {
        console.error(`Malware scan failed for file: ${req.file.originalname} - ${error.message}`);
        res.status(500).json({ error: 'Error during VirusTotal scan', details: error.message });
    }
});

// 5. Network Scan
app.post('/scan-network', async (req, res) => {
    const { subnet } = req.body;

    try {
        console.log(`Network scan started for subnet: ${subnet}`);
        const activeDevices = [];
        for (let i = 1; i <= 255; i++) {
            const ipAddress = `${subnet}${i}`;
            const result = await ping.promise.probe(ipAddress, { timeout: 1 });
            if (result.alive) {
                activeDevices.push(ipAddress);
                console.log(`Active device found: ${ipAddress}`);
            }
            io.emit('network-scan-progress', { progress: Math.round((i / 20) * 100) });
        }

        const networkScanResult = new NetworkScan({ subnet, activeDevices });
        await networkScanResult.save();
        console.log(`Network scan completed for subnet: ${subnet}. Active Devices: ${activeDevices}`);
        io.emit('network-scan-completed', activeDevices);
        res.json(networkScanResult);
    } catch (err) {
        console.error(`Network scan failed for subnet: ${subnet} - ${err.message}`);
        res.status(500).json({ error: 'Network scan failed', details: err.message });
    }
});

// Clear Data Endpoints
app.delete('/clear-ping', async (req, res) => {
    await PingResult.deleteMany({});
    console.log('All Ping results cleared');
    res.json({ message: 'All Ping results cleared' });
});

app.delete('/clear-port-scan', async (req, res) => {
    await PortScan.deleteMany({});
    console.log('All Port Scan results cleared');
    res.json({ message: 'All Port Scan results cleared' });
});

app.delete('/clear-network-scan', async (req, res) => {
    await NetworkScan.deleteMany({});
    console.log('All Network Scan results cleared');
    res.json({ message: 'All Network Scan results cleared' });
});

app.delete('/clear-malware-scan', async (req, res) => {
    await MalwareScan.deleteMany({});
    console.log('All Malware Scan results cleared');
    res.json({ message: 'All Malware Scan results cleared' });
});

app.delete('/clear-scheduled-scan', async (req, res) => {
    await ScheduledScan.deleteMany({});
    console.log('All Scheduled Scans cleared');
    res.json({ message: 'All Scheduled Scans cleared' });
});

// Search Ping Results
app.get('/search-ping', async (req, res) => {
    const { ipAddress } = req.query;
    try {
        const results = await PingResult.find({ ipAddress });
        res.json(results);
    } catch (err) {
        console.error(`Error fetching Ping results for IP: ${ipAddress} - ${err.message}`);
        res.status(500).json({ error: 'Failed to fetch Ping results', details: err.message });
    }
});

// Search Port Scan Results
app.get('/search-port-scan', async (req, res) => {
    const { ipAddress } = req.query;
    try {
        const results = await PortScan.find({ ipAddress });
        res.json(results);
    } catch (err) {
        console.error(`Error fetching Port Scan results for IP: ${ipAddress} - ${err.message}`);
        res.status(500).json({ error: 'Failed to fetch Port Scan results', details: err.message });
    }
});

// Search Network Scan Results
app.get('/search-network-scan', async (req, res) => {
    const { subnet } = req.query;
    try {
        const results = await NetworkScan.find({ subnet: new RegExp(`^${subnet}`) });
        res.json(results);
    } catch (err) {
        console.error(`Error fetching Network Scan results for subnet: ${subnet} - ${err.message}`);
        res.status(500).json({ error: 'Failed to fetch Network Scan results', details: err.message });
    }
});

// Search Malware Scan Results by File Name
app.get('/search-malware-scan', async (req, res) => {
    const { fileName } = req.query;
    try {
        const results = await MalwareScan.find({ fileName: new RegExp(fileName, 'i') });
        res.json(results);
    } catch (err) {
        console.error(`Error fetching Malware Scan results for file: ${fileName} - ${err.message}`);
        res.status(500).json({ error: 'Failed to fetch Malware Scan results', details: err.message });
    }
});

// Search Scheduled Port Scan Results
app.get('/search-scheduled-scan', async (req, res) => {
    const { ipAddress } = req.query;
    try {
        const results = await ScheduledScan.find({ ipAddress });
        res.json(results);
    } catch (err) {
        console.error(`Error fetching Scheduled Scan results for IP: ${ipAddress} - ${err.message}`);
        res.status(500).json({ error: 'Failed to fetch Scheduled Scan results', details: err.message });
    }
});


// Real-time connection
io.on('connection', (socket) => {
    console.log('Client connected to Socket.IO');
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
