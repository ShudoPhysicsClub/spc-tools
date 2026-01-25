// src/mojyu-ru/decrypt-worker.ts

// ===== ユーティリティ関数 =====

function bytesToBigInt(bytes: Uint8Array): bigint {
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

function bitLength(n: bigint): number {
  if (n === 0n) return 0;
  return n.toString(2).length;
}

function bigintToUint8Array(n: bigint, size?: number): Uint8Array {
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
    throw new Error(`数値が大きすぎます`);
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

function modExp(base: bigint, exp: bigint, mod: bigint): bigint {
  let k = 5;
  const bits = bitLength(mod);
  if (bits > 2048) k = 7;
  else if (bits > 1024) k = 6;

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

  const reduce = (T: bigint): bigint => {
    const u = ((T & mask) * nPrime) & mask;
    const x = (T + u * mod) >> modBits;
    return x >= mod ? x - mod : x;
  };

  const tableSize = 1 << (k - 1);
  const table = new Array<bigint>(tableSize);
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
    } else {
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
      for (let s = 0; s < winSize; s++) res = reduce(res * res);
      res = reduce(res * table[Number(winVal >> 1n)]);
      bitPos -= winSize;
    }
  }
  return reduce(res);
}

// ===== SHA-256 =====

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hashBuffer = await globalThis.crypto.subtle.digest('SHA-256', data.buffer as ArrayBuffer);
  return new Uint8Array(hashBuffer);
}

// ===== OAEP関連 =====

function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

async function mgf1(seed: Uint8Array, maskLen: number): Promise<Uint8Array> {
  const hLen = 32;
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

async function oeapUnpad(
  em: Uint8Array,
  k: number,
  label: Uint8Array = new Uint8Array(0),
): Promise<Uint8Array> {
  const hLen = 32;

  if (em.length !== k || k < 2 * hLen + 2) {
    throw new Error('復号エラー: 不正なパディング');
  }

  const lHash = await sha256(label);

  const y = em[0];
  const maskedSeed = em.subarray(1, 1 + hLen);
  const maskedDB = em.subarray(1 + hLen);

  const seedMask = await mgf1(maskedDB, hLen);
  const seed = xorBytes(maskedSeed, seedMask);

  const dbMask = await mgf1(seed, k - hLen - 1);
  const db = xorBytes(maskedDB, dbMask);

  const lHashPrime = db.subarray(0, hLen);

  let lHashMatch = true;
  for (let i = 0; i < hLen; i++) {
    if (lHash[i] !== lHashPrime[i]) {
      lHashMatch = false;
      break;
    }
  }

  let separatorIndex = -1;
  for (let i = hLen; i < db.length; i++) {
    if (db[i] === 0x01) {
      separatorIndex = i;
      break;
    } else if (db[i] !== 0x00) {
      throw new Error('復号エラー: 不正なパディング構造');
    }
  }

  if (y !== 0x00 || !lHashMatch || separatorIndex === -1) {
    throw new Error('復号エラー: パディング検証失敗');
  }

  return db.subarray(separatorIndex + 1);
}

// ===== Worker Message Handler =====

self.onmessage = async (e: MessageEvent) => {
  try {
    const {
      chunks,
      p: pStr,
      q: qStr,
      dp: dpStr,
      dq: dqStr,
      qInv: qInvStr,
      nByteLen,
    } = e.data;

    const p = BigInt(pStr);
    const q = BigInt(qStr);
    const dp = BigInt(dpStr);
    const dq = BigInt(dqStr);
    const qInv = BigInt(qInvStr);

    const results: string[] = [];

    for (const chunkB64 of chunks) {
      // base64 → Uint8Array
      const chunk = Uint8Array.from(atob(chunkB64), c => c.charCodeAt(0));
      const c = bytesToBigInt(chunk);

      // CRT復号
      const cp = c >= p ? c % p : c;
      const cq = c >= q ? c % q : c;

      const m1 = modExp(cp, dp, p);
      const m2 = modExp(cq, dq, q);

      let diff = m1 - m2;
      if (diff < 0n) diff += p;

      const h = (qInv * diff) % p;
      const m = m2 + h * q;

      let paddedMsg = bigintToUint8Array(m, nByteLen);

      // OAEPアンパッド
      let messageChunk: Uint8Array;
      try {
        messageChunk = await oeapUnpad(paddedMsg, nByteLen, new Uint8Array(0));
      } catch {
        // フォールバック
        const filtered = paddedMsg.filter(byte => byte !== 0x00);
        messageChunk = new Uint8Array(filtered);
      }

      // base64エンコード
      const base64 = btoa(String.fromCharCode(...messageChunk));
      results.push(base64);
    }

    self.postMessage({ results });
  } catch (error) {
    self.postMessage({ error: String(error) });
  }
};
