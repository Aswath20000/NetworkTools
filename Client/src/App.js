import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { io } from 'socket.io-client';
import './App.css';

const socket = io('http://localhost:5000'); // Connect to Socket.IO server

function App() {
    // State variables for Ping
    const [ipAddress, setIpAddress] = useState('');
    const [pingResult, setPingResult] = useState(null);

    // State variables for Port Scan
    const [portRange, setPortRange] = useState({ start: 1, end: 100 });
    const [portScanProgress, setPortScanProgress] = useState(0);
    const [portScanResult, setPortScanResult] = useState([]);

    // State variables for Network Scan
    const [subnet, setSubnet] = useState('');
    const [networkScanProgress, setNetworkScanProgress] = useState(0);
    const [activeDevices, setActiveDevices] = useState([]);

    // State variables for File Upload
    const [file, setFile] = useState(null);
    const [fileScanResult, setFileScanResult] = useState(null);
    const [fileUploadProgress, setFileUploadProgress] = useState(0);

    // State for Port Scan Scheduling
    const [interval, setInterval] = useState(0);

    // Socket.IO setup for real-time updates
    useEffect(() => {
        socket.on('port-scan-progress', (data) => setPortScanProgress(data.progress));
        socket.on('port-scan-completed', (ports) => setPortScanResult(ports));
        socket.on('network-scan-progress', (data) => setNetworkScanProgress(data.progress));
        socket.on('network-scan-completed', (devices) => setActiveDevices(devices));

        return () => {
            socket.off('port-scan-progress');
            socket.off('port-scan-completed');
            socket.off('network-scan-progress');
            socket.off('network-scan-completed');
        };
    }, []);

    // Ping Functions
    const handlePing = async () => {
        try {
            const response = await axios.post('http://localhost:5000/ping', { ipAddress });
            setPingResult(response.data);
        } catch (error) {
            alert('Error pinging IP: ' + error.response?.data?.error);
        }
    };

    const clearPingResults = async () => {
        try {
            await axios.delete('http://localhost:5000/clear-ping');
            setPingResult(null);
            alert('Ping results cleared.');
        } catch (error) {
            alert('Error clearing ping results: ' + error.message);
        }
    };

    // Port Scan Functions
    const handlePortScan = async () => {
        try {
            setPortScanProgress(0);
            setPortScanResult([]);
            await axios.post('http://localhost:5000/scan-ports', { ipAddress, portRange });
        } catch (error) {
            alert('Error scanning ports: ' + error.response?.data?.error);
        }
    };

    const clearPortScanResults = async () => {
        try {
            await axios.delete('http://localhost:5000/clear-port-scan');
            setPortScanResult([]);
            setPortScanProgress(0);
            alert('Port scan results cleared.');
        } catch (error) {
            alert('Error clearing port scan results: ' + error.message);
        }
    };

    // Network Scan Functions
    const handleNetworkScan = async () => {
        try {
            setNetworkScanProgress(0);
            setActiveDevices([]);
            await axios.post('http://localhost:5000/scan-network', { subnet });
        } catch (error) {
            alert('Error scanning network: ' + error.response?.data?.error);
        }
    };

    const clearNetworkScanResults = async () => {
        try {
            await axios.delete('http://localhost:5000/clear-network-scan');
            setActiveDevices([]);
            setNetworkScanProgress(0);
            alert('Network scan results cleared.');
        } catch (error) {
            alert('Error clearing network scan results: ' + error.message);
        }
    };

    const handleFileUpload = async () => {
        if (!file) return alert('Please select a file first.');
    
        const formData = new FormData();
        formData.append('file', file);
    
        try {
            const response = await axios.post('http://localhost:5000/scan-file', formData, {
                onUploadProgress: (progressEvent) => {
                    if (progressEvent.lengthComputable) {
                        const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total);
                        setFileUploadProgress(progress);
                    }
                },
            });
            setFileScanResult(response.data);
            alert('Scan completed successfully.');
        } catch (error) {
            alert('Error scanning file: ' + (error.response?.data?.error || error.message));
        }
    };
    
    // Clear Malware Scan Results
    const clearFileScanResults = async () => {
        try {
            await axios.delete('http://localhost:5000/clear-malware-scan');
            setFileScanResult(null);
            setFileUploadProgress(0);
            alert('File scan results cleared.');
        } catch (error) {
            alert('Error clearing file scan results: ' + error.message);
        }
    };
    

    // Scheduled Port Scan Functions
    const handleSchedulePortScan = async () => {
        try {
            if (interval <= 0) {
                alert("Please enter a valid interval in minutes.");
                return;
            }
            if (portRange.start < 1 || portRange.end > 65535 || portRange.start > portRange.end) {
                alert("Please enter a valid port range.");
                return;
            }

            await axios.post('http://localhost:5000/schedule-port-scan', { ipAddress, interval, portRange });
            alert(`Port scan scheduled for ${ipAddress} every ${interval} minute(s) for ports ${portRange.start}-${portRange.end}.`);
        } catch (error) {
            alert('Error scheduling port scan: ' + error.response?.data?.error);
        }
    };

    const clearScheduledScanResults = async () => {
        try {
            await axios.delete('http://localhost:5000/clear-scheduled-scan');
            alert('Scheduled scan results cleared.');
        } catch (error) {
            alert('Error clearing scheduled scan results: ' + error.message);
        }
    };

    return (
        <div className="App">
            <h1>Network Tools</h1>

            {/* Ping Functionality */}
            <div className="card">
                <h2>Ping</h2>
                <input type="text" value={ipAddress} onChange={(e) => setIpAddress(e.target.value)} placeholder="Enter IP Address" />
                <button onClick={handlePing}>Ping</button>
                <button onClick={clearPingResults}>Clear Results</button>
                {pingResult && <pre>{JSON.stringify(pingResult, null, 2)}</pre>}
            </div>

            {/* Port Scan Functionality */}
            <div className="card">
                <h2>Port Scan</h2>
                <input
                    type="number"
                    value={portRange.start}
                    onChange={(e) => setPortRange({ ...portRange, start: parseInt(e.target.value) })}
                    placeholder="Start Port"
                />
                <input
                    type="number"
                    value={portRange.end}
                    onChange={(e) => setPortRange({ ...portRange, end: parseInt(e.target.value) })}
                    placeholder="End Port"
                />
                <button onClick={handlePortScan}>Start Scan</button>
                <button onClick={clearPortScanResults}>Clear Results</button>
                <progress value={portScanProgress} max="100" />
                <ul>
                    {portScanResult.map((port, index) => <li key={index}>Port {port} is open</li>)}
                </ul>
            </div>

            {/* Network Scan Functionality */}
            <div className="card">
                <h2>Network Scan</h2>
                <input type="text" value={subnet} onChange={(e) => setSubnet(e.target.value)} placeholder="Enter Subnet (e.g., 192.168.1.)" />
                <button onClick={handleNetworkScan}>Start Scan</button>
                <button onClick={clearNetworkScanResults}>Clear Results</button>
                <progress value={networkScanProgress} max="100" />
                <ul>
                    {activeDevices.map((device, index) => <li key={index}>{device}</li>)}
                </ul>
            </div>

            <div className="card">
    <h2>Malware Scan</h2>
    <input type="file" onChange={(e) => setFile(e.target.files[0])} />
    <button onClick={handleFileUpload}>Upload and Scan</button>
    <button onClick={clearFileScanResults}>Clear Results</button>
    <h3>Progress:</h3>
    <progress value={fileUploadProgress} max="100" />
    {fileScanResult && (
        <div>
            <h3>{fileScanResult.message}</h3>
            {fileScanResult.details.length > 0 && (
                <ul>
                    {fileScanResult.details.map((item, index) => (
                        <li key={index}>
                            <strong>{item.engine}</strong>: {item.verdict} - {item.description}
                        </li>
                    ))}
                </ul>
            )}
        </div>
    )}
</div>;

            {/* Scheduled Port Scan */}
            <div className="card">
                <h2>Scheduled Port Scan</h2>
                <input type="text" value={ipAddress} onChange={(e) => setIpAddress(e.target.value)} placeholder="Enter IP Address" />
                <input
                    type="number"
                    value={portRange.start}
                    onChange={(e) => setPortRange({ ...portRange, start: parseInt(e.target.value) })}
                    placeholder="Start Port"
                />
                <input
                    type="number"
                    value={portRange.end}
                    onChange={(e) => setPortRange({ ...portRange, end: parseInt(e.target.value) })}
                    placeholder="End Port"
                />
                <input
                    type="number"
                    value={interval}
                    onChange={(e) => setInterval(parseInt(e.target.value))}
                    placeholder="Interval in minutes"
                />
                <button onClick={handleSchedulePortScan}>Schedule Scan</button>
                <button onClick={clearScheduledScanResults}>Clear Scheduled Results</button>
            </div>
        </div>
    );
}

export default App;
