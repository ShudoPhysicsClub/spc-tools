// src/mojyu-ru/encrypt-worker.ts
// prime-worker.tsと同じパターン：全部自己完結
// ===== ユーティリティ関数 =====
function bytesToBigInt(bytes) {
    const len = bytes.length;
    let res = 0n;
    const view = new DataView(bytes.buffer, bytes.byteOffset, len);
    let i = 0;
    for (; i <= len - 8; i += 8) {
        res = (res << 64n) + view.getBigUint64(i);
    }
    for (; i < len; i++) {
        res = (res << 8n) + BigInt(bytes[i]);
    }
    return res;
}
function bitLength(n) {
    if (n === 0n)
        return 0;
    return n.toString(2).length;
}
function bigintToUint8Array(n, size) {
    if (n === 0n) {
        return size ? new Uint8Array(size) : new Uint8Array([0]);
    }
    const bitLen = bitLength(n);
    const minByteLength = (bitLen + 7) >> 3;
    if (size === undefined) {
        const u8 = new Uint8Array(minByteLength);
        let tempN = n;
        for (let i = minByteLength - 1; i >= 0; i--) {
            u8[i] = Number(tempN & 0xffn);
            tempN >>= 8n;
        }
        return u8;
    }
    if (minByteLength > size) {
        throw new Error(`数値が大きすぎます: ${minByteLength}バイト必要、${size}バイト指定`);
    }
    const u8 = new Uint8Array(size);
    let tempN = n;
    for (let i = size - 1; i >= size - minByteLength; i--) {
        u8[i] = Number(tempN & 0xffn);
        tempN >>= 8n;
    }
    return u8;
}
// ===== Montgomery modExp =====
function modExp(base, exp, mod) {
    let k = 5;
    const bits = bitLength(mod);
    if (bits > 2048)
        k = 7;
    else if (bits > 1024)
        k = 6;
    const modBits = BigInt(bits);
    const R = 1n << modBits;
    const mask = R - 1n;
    let t = 0n, newT = 1n, r = R, m = mod;
    while (m !== 0n) {
        const q = r / m;
        [t, newT] = [newT, t - q * newT];
        [r, m] = [m, r - q * m];
    }
    const nPrime = (R - (t < 0n ? t + R : t)) & mask;
    const reduce = (T) => {
        const u = ((T & mask) * nPrime) & mask;
        const x = (T + u * mod) >> modBits;
        return x >= mod ? x - mod : x;
    };
    const tableSize = 1 << (k - 1);
    const table = new Array(tableSize);
    const baseBar = (base << modBits) % mod;
    const baseBar2 = reduce(baseBar * baseBar);
    table[0] = baseBar;
    for (let i = 1; i < tableSize; i++) {
        table[i] = reduce(table[i - 1] * baseBar2);
    }
    let res = (1n << modBits) % mod;
    let bitPos = bitLength(exp) - 1;
    while (bitPos >= 0) {
        const bit = (exp >> BigInt(bitPos)) & 1n;
        if (!bit) {
            res = reduce(res * res);
            bitPos--;
        }
        else {
            let winSize = 1;
            let winVal = 1n;
            const maxWinSize = Math.min(k, bitPos + 1);
            for (let j = 1; j < maxWinSize; j++) {
                winVal = (winVal << 1n) | ((exp >> BigInt(bitPos - j)) & 1n);
                winSize = j + 1;
            }
            while (winSize > 1 && !(winVal & 1n)) {
                winVal >>= 1n;
                winSize--;
            }
            for (let s = 0; s < winSize; s++)
                res = reduce(res * res);
            res = reduce(res * table[Number(winVal >> 1n)]);
            bitPos -= winSize;
        }
    }
    return reduce(res);
}
// ===== SHA-256 =====
async function sha256(data) {
    const hashBuffer = await globalThis.crypto.subtle.digest('SHA-256', data.buffer);
    return new Uint8Array(hashBuffer);
}
// ===== OAEP関連 =====
function xorBytes(a, b) {
    const result = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}
async function mgf1(seed, maskLen) {
    const hLen = 32; // SHA-256
    const result = new Uint8Array(maskLen);
    let offset = 0;
    for (let counter = 0; offset < maskLen; counter++) {
        const c = new Uint8Array(4);
        c[0] = (counter >>> 24) & 0xff;
        c[1] = (counter >>> 16) & 0xff;
        c[2] = (counter >>> 8) & 0xff;
        c[3] = counter & 0xff;
        const concat = new Uint8Array(seed.length + 4);
        concat.set(seed);
        concat.set(c, seed.length);
        const hash = await sha256(concat);
        const toCopy = Math.min(hLen, maskLen - offset);
        result.set(hash.subarray(0, toCopy), offset);
        offset += toCopy;
    }
    return result;
}
async function oeapPad(message, k, label = new Uint8Array(0)) {
    const hLen = 32; // SHA-256
    if (message.length > k - 2 * hLen - 2) {
        throw new Error('メッセージが長すぎます');
    }
    const lHash = await sha256(label);
    const ps = new Uint8Array(k - message.length - 2 * hLen - 2);
    ps.fill(0x00);
    const db = new Uint8Array(k - hLen - 1);
    db.set(lHash, 0);
    db.set(ps, hLen);
    db[hLen + ps.length] = 0x01;
    db.set(message, hLen + ps.length + 1);
    const seed = new Uint8Array(hLen);
    globalThis.crypto.getRandomValues(seed);
    const dbMask = await mgf1(seed, k - hLen - 1);
    const maskedDB = xorBytes(db, dbMask);
    const seedMask = await mgf1(maskedDB, hLen);
    const maskedSeed = xorBytes(seed, seedMask);
    const em = new Uint8Array(k);
    em[0] = 0x00;
    em.set(maskedSeed, 1);
    em.set(maskedDB, 1 + hLen);
    return em;
}
// ===== Worker Message Handler =====
self.onmessage = async (e) => {
    try {
        const { chunks, e: eStr, n: nStr, nByteLen } = e.data;
        const eBigInt = BigInt(eStr);
        const nBigInt = BigInt(nStr);
        const results = [];
        for (const chunkData of chunks) {
            const chunk = new Uint8Array(chunkData);
            // OAEPパディング
            const paddedMsg = await oeapPad(chunk, nByteLen, new Uint8Array(0));
            // 暗号化
            const m = bytesToBigInt(paddedMsg);
            const c = modExp(m, eBigInt, nBigInt);
            const cBytes = bigintToUint8Array(c);
            // 固定長パディング
            const cBytesPadded = new Uint8Array(nByteLen);
            cBytesPadded.set(cBytes, nByteLen - cBytes.length);
            // base64エンコード
            const base64 = btoa(String.fromCharCode(...cBytesPadded));
            results.push(base64);
        }
        self.postMessage({ results });
    }
    catch (error) {
        self.postMessage({ error: String(error) });
    }
};
