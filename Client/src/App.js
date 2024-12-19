import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { io } from 'socket.io-client';
import './App.css';

const socket = io('http://localhost:5000'); 

function App() {
    
    const [ipAddress, setIpAddress] = useState('');
    const [pingResult, setPingResult] = useState(null);
    const [portRange, setPortRange] = useState({ start: 1, end: 100 });
    const [portScanProgress, setPortScanProgress] = useState(0);
    const [portScanResult, setPortScanResult] = useState([]);
    const [subnet, setSubnet] = useState('');
    const [networkScanProgress, setNetworkScanProgress] = useState(0);
    const [activeDevices, setActiveDevices] = useState([]);
    const [file, setFile] = useState(null);
    const [fileScanResult, setFileScanResult] = useState(null);
    const [fileUploadProgress, setFileUploadProgress] = useState(0);
    const [interval, setInterval] = useState(0);
    const [pingSearchTerm, setPingSearchTerm] = useState('');
    const [pingResults, setPingResults] = useState([]);
    const [portScanSearchTerm, setPortScanSearchTerm] = useState('');
    const [portScanResults, setPortScanResults] = useState([]);
    const [networkScanSearchTerm, setNetworkScanSearchTerm] = useState('');
    const [networkScanResults, setNetworkScanResults] = useState([]);
    const [malwareSearchTerm, setMalwareSearchTerm] = useState('');
    const [malwareResults, setMalwareResults] = useState([]);
    const [scheduledScanSearchTerm, setScheduledScanSearchTerm] = useState('');
    const [scheduledScanResults, setScheduledScanResults] = useState([]);

    const handlePingSearch = async () => {
        try {
            const response = await axios.get('http://localhost:5000/search-ping', {
                params: { ipAddress: pingSearchTerm },
            });
            setPingResults(response.data);
        } catch (error) {
            alert('Error fetching Ping results: ' + error.message);
        }
    };

    const handlePortScanSearch = async () => {
        try {
            const response = await axios.get('http://localhost:5000/search-port-scan', {
                params: { ipAddress: portScanSearchTerm },
            });
            setPortScanResults(response.data);
        } catch (error) {
            alert('Error fetching Port Scan results: ' + error.message);
        }
    };

    const handleNetworkScanSearch = async () => {
        try {
            const response = await axios.get('http://localhost:5000/search-network-scan', {
                params: { subnet: networkScanSearchTerm },
            });
            setNetworkScanResults(response.data);
        } catch (error) {
            alert('Error fetching Network Scan results: ' + error.message);
        }
    };

    const handleMalwareSearch = async () => {
        try {
            const response = await axios.get('http://localhost:5000/search-malware-scan', {
                params: { fileName: malwareSearchTerm },
            });
            setMalwareResults(response.data);
        } catch (error) {
            alert('Error fetching Malware Scan results: ' + error.message);
        }
    };

    const handleScheduledScanSearch = async () => {
        try {
            const response = await axios.get('http://localhost:5000/search-scheduled-scan', {
                params: { ipAddress: scheduledScanSearchTerm },
            });
            setScheduledScanResults(response.data);
        } catch (error) {
            alert('Error fetching Scheduled Scan results: ' + error.message);
        }
    };

    useEffect(() => {
        socket.on('port-scan-progress', (data) => setPortScanProgress(data.progress));
        socket.on('port-scan-completed', (ports) => {
            console.log(`Port scan completed. Open ports: ${ports}`);
            setPortScanResult(ports);
        });
        socket.on('network-scan-progress', (data) => setNetworkScanProgress(data.progress));
        socket.on('network-scan-completed', (devices) => {
            console.log(`Network scan completed. Active devices: ${devices}`);
            setActiveDevices(devices);
        });
    
        // Handle socket errors
        socket.on('connect_error', (error) => {
            console.error('Socket connection error:', error);
            alert('Socket connection error. Please try again.');
        });
    
        // Clean up socket listeners on unmount
        return () => {
            socket.off('port-scan-progress');
            socket.off('port-scan-completed');
            socket.off('network-scan-progress');
            socket.off('network-scan-completed');
            socket.off('connect_error');
        };
    }, []);
    

    
    const handlePing = async () => {
        console.log('Ping started...');
        try {
            const response = await axios.post('http://localhost:5000/ping', { ipAddress });
            setPingResult(response.data);
            console.log('Ping completed:', response.data);
        } catch (error) {
            console.error('Error pinging IP:', error.response?.data?.error || error.message);
            alert('Error pinging IP.');
        }
    };

    const clearPingResults = async () => {
        console.log('Clearing ping results...');
        try {
            await axios.delete('http://localhost:5000/clear-ping');
            setPingResult(null);
            console.log('Ping results cleared.');
            alert('Ping results cleared.');
        } catch (error) {
            console.error('Error clearing ping results:', error.message);
            alert('Error clearing ping results.');
        }
    };

    const handlePortScan = async () => {
        console.log('Port scan started...');
        try {
            setPortScanProgress(0);
            setPortScanResult([]);
            await axios.post('http://localhost:5000/scan-ports', { ipAddress, portRange });
        } catch (error) {
            console.error('Error scanning ports:', error.response?.data?.error || error.message);
            alert('Error scanning ports.');
        }
    };

    const clearPortScanResults = async () => {
        console.log('Clearing port scan results...');
        try {
            await axios.delete('http://localhost:5000/clear-port-scan');
            setPortScanResult([]);
            setPortScanProgress(0);
            console.log('Port scan results cleared.');
            alert('Port scan results cleared.');
        } catch (error) {
            console.error('Error clearing port scan results:', error.message);
            alert('Error clearing port scan results.');
        }
    };

    const handleNetworkScan = async () => {
        console.log('Network scan started...');
        try {
            setNetworkScanProgress(0);
            setActiveDevices([]);
            await axios.post('http://localhost:5000/scan-network', { subnet });
        } catch (error) {
            console.error('Error scanning network:', error.response?.data?.error || error.message);
            alert('Error scanning network.');
        }
    };

    const clearNetworkScanResults = async () => {
        console.log('Clearing network scan results...');
        try {
            await axios.delete('http://localhost:5000/clear-network-scan');
            setActiveDevices([]);
            setNetworkScanProgress(0);
            console.log('Network scan results cleared.');
            alert('Network scan results cleared.');
        } catch (error) {
            console.error('Error clearing network scan results:', error.message);
            alert('Error clearing network scan results.');
        }
    };

    const handleFileUpload = async () => {
        console.log('Malware scan started...');
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
            console.log('Malware scan completed:', response.data);
            alert('Malware scan completed successfully.');
        } catch (error) {
            console.error('Error scanning file:', error.response?.data?.error || error.message);
            alert('Error scanning file.');
        }
    };

    const clearFileScanResults = async () => {
        console.log('Clearing malware scan results...');
        try {
            await axios.delete('http://localhost:5000/clear-malware-scan');
            setFileScanResult(null);
            setFileUploadProgress(0);
            console.log('Malware scan results cleared.');
            alert('Malware scan results cleared.');
        } catch (error) {
            console.error('Error clearing malware scan results:', error.message);
            alert('Error clearing malware scan results.');
        }
    };
    const handleSchedulePortScan = async () => {
        console.log('Scheduling port scan...');
        try {
            if (interval <= 0) {
                alert('Please enter a valid interval in minutes.');
                return;
            }
            if (portRange.start < 1 || portRange.end > 65535 || portRange.start > portRange.end) {
                alert('Please enter a valid port range.');
                return;
            }

            await axios.post('http://localhost:5000/schedule-port-scan', { ipAddress, interval, portRange });
            console.log(`Port scan scheduled for ${ipAddress} every ${interval} minute(s).`);
            alert(`Port scan scheduled for ${ipAddress} every ${interval} minute(s).`);
        } catch (error) {
            console.error('Error scheduling port scan:', error.response?.data?.error || error.message);
            alert('Error scheduling port scan.');
        }
    };

    const clearScheduledScanResults = async () => {
        console.log('Clearing scheduled scan results...');
        try {
            await axios.delete('http://localhost:5000/clear-scheduled-scan');
            console.log('Scheduled scan results cleared.');
            alert('Scheduled scan results cleared.');
        } catch (error) {
            console.error('Error clearing scheduled scan results:', error.message);
            alert('Error clearing scheduled scan results.');
        }
    };

    const handleStopNetworkScan = async () => {
        console.log('Stop network scan requested.');
        try {
            await axios.post('http://localhost:5000/stop-network-scan');
            alert('Network scan will stop shortly.');
            setNetworkScanProgress(0); 
        } catch (error) {
            console.error('Error stopping network scan:', error.response?.data?.error || error.message);
            alert('Error stopping network scan.');
        }
    };

    return (
        <div className="App">
            <h1>Network Tools</h1>
            <div className='card-cont'>
            <div className="card">
                <h2>Ping</h2>
                <input type="text" value={ipAddress} onChange={(e) => setIpAddress(e.target.value)} placeholder="Enter IP Address" />
                <button onClick={handlePing}>Ping</button>
                <button onClick={clearPingResults}>Clear Results</button>
                {pingResult && <pre>{JSON.stringify(pingResult, null, 2)}</pre>}
            </div>

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
                    {portScanResult.map((port, index) => (
                        <li key={index}>Port {port} is open</li>
                    ))}
                </ul>
            </div>

            
            <div className="card">
                <h2>Network Scan</h2>
                <input type="text" value={subnet} onChange={(e) => setSubnet(e.target.value)} placeholder="Enter Subnet (e.g., 192.168.1.)" />
                <button onClick={handleNetworkScan}>Start Scan</button>
                <button onClick={clearNetworkScanResults}>Clear Results</button>

                <button onClick={handleStopNetworkScan}>
        Stop Scan
    </button>               
     <progress value={networkScanProgress} max="100" />
                <ul>
                    {activeDevices.map((device, index) => (
                        <li key={index}>{device}</li>
                    ))}
                </ul>
            </div>

            
            <div className="card">
                <h2>Malware Scan</h2>
                <input type="file" onChange={(e) => setFile(e.target.files[0])} />
                <button onClick={handleFileUpload}>Upload and Scan</button>
                <button onClick={clearFileScanResults}>Clear Results</button>
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
            </div>

            
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
            </div></div>

            <h1>History</h1>
<div className='card-cont'>
            <div className="card">
                <h2>Ping History</h2>
                <input
                    type="text"
                    value={pingSearchTerm}
                    onChange={(e) => setPingSearchTerm(e.target.value)}
                    placeholder="Enter IP Address"
                />
                <button onClick={handlePingSearch}>Search Ping</button>
                {pingResults.length > 0 && (
                    <table>
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Alive</th>
                                <th>Time</th>
                                <th>Timestamp</th>
                            </tr>
                        </thead>
                        <tbody>
                            {pingResults.map((result, index) => (
                                <tr key={index}>
                                    <td>{result.ipAddress}</td>
                                    <td>{result.alive ? 'Yes' : 'No'}</td>
                                    <td>{result.time}</td>
                                    <td>{new Date(result.timestamp).toLocaleString()}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            
            <div className="card">
                <h2>Port Scan History</h2>
                <input
                    type="text"
                    value={portScanSearchTerm}
                    onChange={(e) => setPortScanSearchTerm(e.target.value)}
                    placeholder="Enter IP Address"
                />
                <button onClick={handlePortScanSearch}>Search Port Scan</button>
                {portScanResults.length > 0 && (
                    <table>
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Open Ports</th>
                                <th>Timestamp</th>
                            </tr>
                        </thead>
                        <tbody>
                            {portScanResults.map((result, index) => (
                                <tr key={index}>
                                    <td>{result.ipAddress}</td>
                                    <td>{result.openPorts?.join(', ') || 'None'}</td>
                                    <td>{new Date(result.timestamp).toLocaleString()}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            
            <div className="card">
                <h2>Network Scan History</h2>
                <input
                    type="text"
                    value={networkScanSearchTerm}
                    onChange={(e) => setNetworkScanSearchTerm(e.target.value)}
                    placeholder="Enter Subnet (e.g., 192.168.1.)"
                />
                <button onClick={handleNetworkScanSearch}>Search Network Scan</button>
                {networkScanResults.length > 0 && (
                    <table>
                        <thead>
                            <tr>
                                <th>Subnet</th>
                                <th>Active Devices</th>
                                <th>Timestamp</th>
                            </tr>
                        </thead>
                        <tbody>
                            {networkScanResults.map((result, index) => (
                                <tr key={index}>
                                    <td>{result.subnet}</td>
                                    <td>{result.activeDevices?.join(', ') || 'None'}</td>
                                    <td>{new Date(result.timestamp).toLocaleString()}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            <div className="card">
                <h2>Malware Scan History</h2>
                <input
                    type="text"
                    value={malwareSearchTerm}
                    onChange={(e) => setMalwareSearchTerm(e.target.value)}
                    placeholder="Enter File Name (e.g., file.txt)"
                />
                <button onClick={handleMalwareSearch}>Search Malware Scan</button>
                {malwareResults.length > 0 && (
                    <table>
                        <thead>
                            <tr>
                                <th>File Name</th>
                                <th>Result</th>
                                <th>Timestamp</th>
                            </tr>
                        </thead>
                        <tbody>
                            {malwareResults.map((result, index) => (
                                <tr key={index}>
                                    <td>{result.fileName}</td>
                                    <td>{result.result.message}</td>
                                    <td>{new Date(result.timestamp).toLocaleString()}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            <div className="card">
    <h2>Scheduled Scan History</h2>
    <input
        type="text"
        value={scheduledScanSearchTerm}
        onChange={(e) => setScheduledScanSearchTerm(e.target.value)}
        placeholder="Enter IP Address"
    />
    <button onClick={handleScheduledScanSearch}>Search Scheduled Scans</button>
    {scheduledScanResults.length > 0 && (
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Scan History</th>
                    <th>Last Executed</th>
                    <th>Created At</th>
                </tr>
            </thead>
            <tbody>
                {scheduledScanResults.map((result, index) => (
                    <tr key={index}>
                        <td>{result.ipAddress}</td>
                        <td>
                            {/* Display only openPorts from scanHistory */}
                            {result.scanHistory && result.scanHistory.length > 0 ? (
                                result.scanHistory.map((scan, scanIndex) => (
                                    <span key={scanIndex}>
                                        {`Open Ports: ${scan.openPorts.join(', ')}`}
                                        <br />
                                    </span>
                                ))
                            ) : (
                                'No Scan History'
                            )}
                        </td>
                        <td>{new Date(result.lastExecuted).toLocaleString()}</td>
                        <td>{new Date(result.createdAt).toLocaleString()}</td>
                    </tr>
                ))}
            </tbody>
        </table>
    )}
</div>
</div></div>
    );
}

export default App;
