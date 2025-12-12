import net from 'net';
import tls from 'tls';
import { Buffer } from 'buffer';
import WebSocket from 'ws'; 

// --- CONFIGURATION ---
const userID = '8e593eef-60b3-471b-821b-1fb89389032b'; // REPLACE WITH YOUR UUID
const proxyHost = "159.203.88.245"; // Your upstream proxy host/IP
const proxyPort = 443; 

// --- SECURITY AND UTILS ---
const SECURITY_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
};

function isValidUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

function generateAllLinks(host) {
    // The VLESS path is adjusted to match the Vercel function path: /api/vless
    return [
        `vless://${userID}@${host}:443?encryption=none&security=tls&sni=${host}&type=ws&path=/api/vless#Vercel-${host}`,
        `vmess://${userID}@${host}:443?encryption=none&security=tls&sni=${host}&type=ws&path=/api/vless#Vercel-${host}`
    ];
}

function generateResponseText(host) {
    const location = process.env.VERCEL_REGION || 'Unknown/Global';
    return `VLESS Proxy Service\nHost: ${host}\nLocation: ${location}\nStatus: Active\nUUID: ${userID}`;
}

// --- PROXY HANDLERS ---
function processProxyHeader(chunk, expectedUserID) {
    if (chunk.length < 36) return { hasError: true, message: 'Invalid header: payload too short' };
    
    // Check for the UUID at the start of the payload
    const headerUserID = chunk.slice(0, 36).toString('utf-8'); 

    if (headerUserID !== expectedUserID) return { hasError: true, message: 'Invalid UUID' };

    return { 
        hasError: false, 
        addressRemote: proxyHost, 
        portRemote: proxyPort, 
        rawDataIndex: 36, // Start of the VLESS/VMess payload after the UUID
        isUDP: false 
    };
}

// Socket-to-Socket data piping
function pipeSockets(remoteSocket, websocket) {
    remoteSocket.on('data', (data) => {
        try {
            websocket.send(data);
        } catch (e) {
            console.error('WS send error (pipe):', e);
            remoteSocket.destroy();
        }
    });

    websocket.on('message', (message) => {
        try {
            remoteSocket.write(message);
        } catch (e) {
            console.error('Remote write error (pipe):', e);
            websocket.close();
        }
    });

    // Handle closure/error events
    remoteSocket.on('error', (err) => {
        console.error('Remote socket error:', err);
        websocket.close();
    });
    remoteSocket.on('close', () => {
        console.log('Remote socket closed.');
        websocket.close();
    });
    websocket.on('close', () => {
        console.log('Client WS closed.');
        remoteSocket.destroy();
    });
    websocket.on('error', (err) => {
        console.error('Client WS error:', err);
        remoteSocket.destroy();
    });
}


// --- MAIN VERCEL HANDLER ---
export default async function handler(req, res) {
    if (!isValidUUID(userID)) {
        res.writeHead(500, {'Content-Type': 'text/plain'});
        return res.end('Invalid UUID in configuration');
    }

    const { url, headers, method } = req;
    const { pathname, host } = new URL(url, `https://${headers.host}`);
    
    // 1. OPTIONS/CORS Bypass
    if (method === 'OPTIONS') {
        res.writeHead(200, SECURITY_HEADERS);
        return res.end();
    }

    // 2. Subscription/Config Endpoint
    if (['/api/vless/sub', '/api/vless/subscribe', '/api/vless/config'].includes(pathname)) {
        const base64Links = Buffer.from(generateAllLinks(host).join('\n')).toString('base64');
        res.writeHead(200, { 
            ...SECURITY_HEADERS,
            "Content-Type": "text/plain;charset=utf-8" 
        });
        return res.end(base64Links);
    }

    // 3. WebSocket Upgrade
    const upgradeHeader = headers['upgrade']?.toLowerCase();
    
    if (upgradeHeader === 'websocket') {
        const key = headers['sec-websocket-key'];
        if (!key) {
            res.writeHead(400); 
            return res.end('Missing Sec-WebSocket-Key');
        }
        
        // This relies on Vercel/Node.js providing the raw socket (res.socket)
        if (res.socket) {
            const rawSocket = res.socket;
            
            // Create a dummy HTTP server to handle the upgrade event gracefully
            const server = new (require('events').EventEmitter)();
            rawSocket.server = server; // Attach the dummy server to the socket

            server.once('upgrade', async (req, socket, head) => {
                
                // Use the 'ws' library to finalize the WebSocket handshake
                new WebSocket.Server({ noServer: true })
                    .handleUpgrade(req, socket, head, (websocket) => {
                        console.log('WebSocket connection established.');
                        
                        let remoteSocket = null;
                        
                        // Client sends initial VLESS header on first message
                        websocket.once('message', (message) => {
                            const messageBuffer = Buffer.from(message);
                            const { hasError, message: errorMessage, addressRemote, portRemote, rawDataIndex } = processProxyHeader(messageBuffer, userID);

                            if (hasError) {
                                console.error(`Proxy header error: ${errorMessage}`);
                                return websocket.close(1008, errorMessage);
                            }

                            // Connect to Upstream Proxy
                            const connectFunction = (portRemote === 443) ? tls.connect : net.connect;
                            
                            remoteSocket = connectFunction({ 
                                host: addressRemote, 
                                port: portRemote, 
                                rejectUnauthorized: false
                            });

                            remoteSocket.on('secureConnect', () => {
                                console.log('Upstream TLS connection established. Starting pipe.');
                                
                                // Send the VLESS payload and start piping
                                const vlessPayload = messageBuffer.slice(rawDataIndex);
                                remoteSocket.write(vlessPayload);
                                pipeSockets(remoteSocket, websocket);
                            });
                            
                            remoteSocket.on('error', (err) => {
                                console.error('Upstream connection failed:', err);
                                websocket.close(1011, 'Upstream connection error');
                            });
                        });
                    }
                );
            });
            
            // Manually switch the protocol and emit the upgrade event
            res.writeHead(101, {
                'Upgrade': 'websocket',
                'Connection': 'Upgrade'
            });
            
            // This is required to make the Node.js server trigger the 'upgrade' event
            server.emit('upgrade', req, rawSocket, Buffer.alloc(0));

            return; // Protocol switch handled
        } else {
            // Fallback for Vercel contexts where raw socket is unavailable
            res.writeHead(503, SECURITY_HEADERS);
            return res.end('WebSocket handshake failed (Raw socket unavailable).');
        }
    }

    // 4. Default Response
    res.writeHead(200, {
        ...SECURITY_HEADERS,
        "Content-Type": "text/plain;charset=utf-8"
     });
    res.end(generateResponseText(host));
                    }
