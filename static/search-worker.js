// Web Worker for payload search - offloads expensive byte-by-byte search from UI thread

// Decode base64 to Uint8Array
function base64ToBytes(base64) {
    const binStr = atob(base64);
    const bytes = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) {
        bytes[i] = binStr.charCodeAt(i);
    }
    return bytes;
}

// Convert string to lowercase byte array
function stringToBytes(str) {
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        bytes[i] = str.charCodeAt(i);
    }
    return bytes;
}

// Lowercase a byte array in place (ASCII only)
function toLowerBytes(bytes) {
    const out = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i];
        out[i] = (b >= 65 && b <= 90) ? b + 32 : b;
    }
    return out;
}

// Search for query bytes in payload (case-insensitive)
function searchInPayload(payloadLower, queryBytes) {
    if (queryBytes.length === 0 || queryBytes.length > payloadLower.length) return false;
    for (let i = 0; i <= payloadLower.length - queryBytes.length; i++) {
        let found = true;
        for (let j = 0; j < queryBytes.length; j++) {
            if (payloadLower[i + j] !== queryBytes[j]) {
                found = false;
                break;
            }
        }
        if (found) return true;
    }
    return false;
}

// Get preview string around match
function getPayloadPreview(payloadBytes, payloadLower, queryBytes) {
    let matchPos = -1;
    for (let i = 0; i <= payloadLower.length - queryBytes.length; i++) {
        let found = true;
        for (let j = 0; j < queryBytes.length; j++) {
            if (payloadLower[i + j] !== queryBytes[j]) {
                found = false;
                break;
            }
        }
        if (found) { matchPos = i; break; }
    }
    if (matchPos === -1) return '';

    const start = Math.max(0, matchPos - 20);
    const end = Math.min(payloadBytes.length, matchPos + queryBytes.length + 20);
    let preview = '';
    for (let i = start; i < end; i++) {
        const b = payloadBytes[i];
        preview += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
    }
    return preview.length > 50 ? preview.substring(0, 47) + '...' : preview;
}

// Handle search requests from main thread
self.onmessage = function(e) {
    const { packets, query, requestId } = e.data;
    const queryLower = query.toLowerCase();
    const queryBytes = stringToBytes(queryLower);
    const results = []; // Array of { packetId, src, preview }

    for (const packet of packets) {
        if (!packet.payload) continue;
        try {
            const payloadBytes = base64ToBytes(packet.payload);
            const payloadLower = toLowerBytes(payloadBytes);

            if (searchInPayload(payloadLower, queryBytes)) {
                const preview = getPayloadPreview(payloadBytes, payloadLower, queryBytes);
                results.push({
                    packetId: packet.id,
                    src: packet.src,
                    srcPort: packet.srcPort,
                    dst: packet.dst,
                    dstPort: packet.dstPort,
                    protocol: packet.protocol,
                    preview: preview
                });
            }
        } catch (err) {
            // Skip packets that fail to decode
        }
    }

    self.postMessage({ requestId, results });
};
