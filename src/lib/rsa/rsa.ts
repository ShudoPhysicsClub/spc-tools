class RSA {
  private smallPrimes: Uint32Array | null = null;

  public async initAsync(binPath: string): Promise<void> {
    const response = await fetch(binPath);
    const buffer = await response.arrayBuffer();
    this.smallPrimes = new Uint32Array(buffer);
  }

  private async sha256(data: Uint8Array): Promise<Uint8Array> {
    const hashBuffer = await crypto.subtle.digest(
      "SHA-256",
      data.buffer as ArrayBuffer,
    );
    return new Uint8Array(hashBuffer);
  }

  private async mgf1(
    seed: Uint8Array,
    maskLen: number,
    onProgress?: (current: number, total: number) => void,
  ): Promise<Uint8Array> {
    const hLen = 32;
    const mask = new Uint8Array(maskLen);
    let offset = 0;
    let counter = 0;

    const totalIterations = Math.ceil(maskLen / hLen);

    while (offset < maskLen) {
      const counterBytes = new Uint8Array(4);
      counterBytes[0] = (counter >>> 24) & 0xff;
      counterBytes[1] = (counter >>> 16) & 0xff;
      counterBytes[2] = (counter >>> 8) & 0xff;
      counterBytes[3] = counter & 0xff;

      const input = new Uint8Array(seed.length + 4);
      input.set(seed);
      input.set(counterBytes, seed.length);

      const hash = await this.sha256(input);
      const copyLen = Math.min(hash.length, maskLen - offset);
      mask.set(hash.subarray(0, copyLen), offset);

      offset += copyLen;
      counter++;

      if (onProgress && counter % 10 === 0) {
        onProgress(counter, totalIterations);
      }
    }

    if (onProgress) {
      onProgress(totalIterations, totalIterations);
    }

    return mask;
  }

  private xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
    const result = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) {
      result[i] = a[i] ^ b[i];
    }
    return result;
  }

  private async oeapPad(
    message: Uint8Array,
    k: number,
    label: Uint8Array = new Uint8Array(0),
    onProgress?: (stage: string, progress: number) => void,
  ): Promise<Uint8Array> {
    const hLen = 32;
    const mLen = message.length;

    if (mLen > k - 2 * hLen - 2) {
      alert("メッセージが長すぎます。パディングを考慮すると、RSA-" + (k * 8) + "bitでは約" + (k - 2 * hLen - 2) + "バイトまでです。");
      throw new Error(
        `メッセージが長すぎます。パディングを考慮すると、RSA-${k * 8}bitでは約${k - 2 * hLen - 2}バイトまでです。`,
      );
    }

    onProgress?.("lHash計算中", 0);
    const lHash = await this.sha256(label);

    const psLen = k - mLen - 2 * hLen - 2;
    const ps = new Uint8Array(psLen);

    onProgress?.("DB構築中", 5);
    const db = new Uint8Array(k - hLen - 1);
    db.set(lHash, 0);
    db.set(ps, hLen);
    db[hLen + psLen] = 0x01;
    db.set(message, hLen + psLen + 1);

    const seed = new Uint8Array(hLen);
    crypto.getRandomValues(seed);

    onProgress?.("dbMask生成中", 10);
    const dbMask = await this.mgf1(seed, k - hLen - 1, (cur, total) => {
      const percent = 10 + (cur / total) * 40;
      onProgress?.(`dbMask生成中 (${cur}/${total})`, percent);
    });

    onProgress?.("maskedDB計算中", 50);
    const maskedDB = this.xorBytes(db, dbMask);

    onProgress?.("seedMask生成中", 55);
    const seedMask = await this.mgf1(maskedDB, hLen, (cur, total) => {
      const percent = 55 + (cur / total) * 35;
      onProgress?.(`seedMask生成中 (${cur}/${total})`, percent);
    });

    onProgress?.("最終処理中", 90);
    const maskedSeed = this.xorBytes(seed, seedMask);

    const em = new Uint8Array(k);
    em[0] = 0x00;
    em.set(maskedSeed, 1);
    em.set(maskedDB, 1 + hLen);

    onProgress?.("パディング完了", 100);
    return em;
  }

  private async oeapUnpad(
    em: Uint8Array,
    k: number,
    label: Uint8Array = new Uint8Array(0),
    onProgress?: (stage: string, progress: number) => void,
  ): Promise<Uint8Array> {
    const hLen = 32;

    if (em.length !== k || k < 2 * hLen + 2) {
      throw new Error("復号エラー: 不正なパディング");
    }

    onProgress?.("lHash計算中", 0);
    const lHash = await this.sha256(label);

    onProgress?.("EM分解中", 5);
    const y = em[0];
    const maskedSeed = em.subarray(1, 1 + hLen);
    const maskedDB = em.subarray(1 + hLen);

    onProgress?.("seedMask生成中", 10);
    const seedMask = await this.mgf1(maskedDB, hLen, (cur, total) => {
      const percent = 10 + (cur / total) * 40;
      onProgress?.(`seedMask生成中 (${cur}/${total})`, percent);
    });

    onProgress?.("seed復元中", 50);
    const seed = this.xorBytes(maskedSeed, seedMask);

    onProgress?.("dbMask生成中", 55);
    const dbMask = await this.mgf1(seed, k - hLen - 1, (cur, total) => {
      const percent = 55 + (cur / total) * 35;
      onProgress?.(`dbMask生成中 (${cur}/${total})`, percent);
    });

    onProgress?.("DB復元中", 90);
    const db = this.xorBytes(maskedDB, dbMask);

    onProgress?.("検証中", 95);
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
        throw new Error("復号エラー: 不正なパディング構造");
      }
    }

    if (y !== 0x00 || !lHashMatch || separatorIndex === -1) {
      throw new Error("復号エラー: パディング検証失敗");
    }

    onProgress?.("メッセージ抽出完了", 100);
    const message = db.subarray(separatorIndex + 1);
    return message;
  }

  private encryptWorkers: Worker[] = [];
  private decryptWorkers: Worker[] = [];
  private workerCount = 4;
  private workersInitialized = false;
  
  // Worker初期化
  private initWorkers() {
  if (this.workersInitialized) return;
  
  try {
    for (let i = 0; i < this.workerCount; i++) {
      const encWorker = new Worker('./dist/mojyu-ru/encrypt-worker.js');
      const decWorker = new Worker('./dist/mojyu-ru/decrypt-worker.js');
      
      // エラーハンドラ追加
      encWorker.onerror = (e) => {
        console.error('🔴 Encrypt Worker エラー:', e);
        console.error('🔴 メッセージ:', e.message);
        console.error('🔴 ファイル:', e.filename);
      };
      
      decWorker.onerror = (e) => {
        console.error('🔴 Decrypt Worker エラー:', e);
        console.error('🔴 メッセージ:', e.message);
        console.error('🔴 ファイル:', e.filename);
      };
      
      this.encryptWorkers.push(encWorker);
      this.decryptWorkers.push(decWorker);
    }
    this.workersInitialized = true;
    console.log('✅ Worker並列化 初期化成功');
  } catch (err) {
    console.error('❌ Worker初期化で例外:', err);
    console.warn('⚠️ Worker初期化失敗、メインスレッドで実行します', err);
  }
  }
  
  // ===== 既存のencryptStringToBase64を書き換え =====
  
  public async encryptStringToBase64(
    text: string,
    e: bigint,
    n: bigint,
    onProgress?: (stage: string, progress: number) => void,
  ): Promise<string> {
    const msgBin = new TextEncoder().encode(text);
    const nByteLen = Math.ceil(this.bitLength(n) / 8);
    const maxChunkSize = nByteLen - 66;

    // ブロック分割
    const chunks: Uint8Array[] = [];
    for (let i = 0; i < msgBin.length; i += maxChunkSize) {
      chunks.push(msgBin.slice(i, i + maxChunkSize));
    }
    
    // Worker使えるなら並列処理、ダメならメインスレッド
    this.initWorkers();
    
    if (this.workersInitialized && chunks.length > 10) {
      // 10ブロック以上なら並列処理
      return this.encryptParallel(chunks, e, n, nByteLen, onProgress);
    } else {
      // 既存のメインスレッド版
      return this.encryptSequential(chunks, e, n, nByteLen, onProgress);
    }
  }
  
  // メインスレッド版（既存のコードをここに移動）
  private async encryptSequential(
    chunks: Uint8Array[],
    e: bigint,
    n: bigint,
    nByteLen: number,
    onProgress?: (stage: string, progress: number) => void,
  ): Promise<string> {
    const encryptedChunks: Uint8Array[] = [];
    
    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i];
      
      const paddedMsg = await this.oeapPad(chunk, nByteLen, new Uint8Array(0));
      const m = this.bytesToBigInt(paddedMsg);
      const c = this.modExp(m, e, n);
      const cBytes = this.bigintToUint8Array(c);
      
      const cBytesPadded = new Uint8Array(nByteLen);
      cBytesPadded.set(cBytes, nByteLen - cBytes.length);
      
      encryptedChunks.push(cBytesPadded);
      
      onProgress?.(
        "暗号化進行中", 
        Math.floor(((i + 1) / chunks.length) * 100)
      );
    }
    
    const totalEncryptedLength = encryptedChunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const combinedEncrypted = new Uint8Array(totalEncryptedLength);
    let offset = 0;
    for (const chunk of encryptedChunks) {
      combinedEncrypted.set(chunk, offset);
      offset += chunk.length;
    }
    
    return this.bytesToBase64(combinedEncrypted);
  }
  
  // Worker並列版
  private async encryptParallel(
    chunks: Uint8Array[],
    e: bigint,
    n: bigint,
    nByteLen: number,
    onProgress?: (stage: string, progress: number) => void,
  ): Promise<string> {
    const chunksPerWorker = Math.ceil(chunks.length / this.workerCount);
    
    const promises = this.encryptWorkers.map((worker, idx) => {
      const start = idx * chunksPerWorker;
      const end = Math.min(start + chunksPerWorker, chunks.length);
      const workerChunks = chunks.slice(start, end);
      
      if (workerChunks.length === 0) return Promise.resolve([]);
      
      return new Promise<Uint8Array[]>((resolve) => {
        worker.onmessage = (event) => {
          // エラーチェック
          if (event.data.error) {
            console.error('❌ Worker内でエラー:', event.data.error);
            resolve([]);
            return;
          }
          
          if (!event.data.results) {
            console.error('❌ results が undefined!');
            resolve([]);
            return;
          }
          
          // base64文字列配列 → Uint8Array配列に戻す
          const base64Results: string[] = event.data.results;
          const uint8Results = base64Results.map(b64 => 
            Uint8Array.from(atob(b64), c => c.charCodeAt(0))
          );
          resolve(uint8Results);
        };
        
        worker.onerror = (err) => {
          console.error('❌ Workerエラー:', err);
          resolve([]);
        };
        
        worker.postMessage({
          chunks: workerChunks,
          e: e.toString(), // BigInt → 文字列
          n: n.toString(),
          nByteLen,
        });
      });
    });
    
    onProgress?.("並列暗号化中", 50);
    
    const results = await Promise.all(promises);
    
    // 結果を順番通りに結合
    const allChunks = results.flat();
    const totalLength = allChunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const combined = new Uint8Array(totalLength);
    
    let offset = 0;
    for (const chunk of allChunks) {
      combined.set(chunk, offset);
      offset += chunk.length;
    }
    
    onProgress?.("暗号化完了", 100);
    
    return this.bytesToBase64(combined);
  }
  
  // ===== 既存のdecryptBase64ToStringを書き換え =====
  
  public async decryptBase64ToString(
    b64Cipher: string,
    d: bigint,
    p: bigint,
    q: bigint,
    n: bigint,
    onProgress?: (stage: string, progress: number) => void,
    dp?: bigint,
    dq?: bigint,
    qInv?: bigint,
  ): Promise<string> {
    const cipherBin = this.base64ToBytes(b64Cipher);
    const nByteLen = Math.ceil(this.bitLength(n) / 8);
    
    // ブロックに分割
    const chunks: Uint8Array[] = [];
    const totalBlocks = cipherBin.length / nByteLen;
    for (let i = 0; i < totalBlocks; i++) {
      const start = i * nByteLen;
      chunks.push(cipherBin.slice(start, start + nByteLen));
    }
    
    this.initWorkers();
    
    if (this.workersInitialized && chunks.length > 10) {
      // 10ブロック以上なら並列処理
      return this.decryptParallel(chunks, d, p, q, n, nByteLen, onProgress, dp, dq, qInv);
    } else {
      // 既存のメインスレッド版
      return this.decryptSequential(chunks, d, p, q, n, nByteLen, onProgress, dp, dq, qInv);
    }
  }
  
  // メインスレッド版（既存のコードをここに移動）
// src/mojyu-ru/rsa.ts の decryptSequential メソッド

private async decryptSequential(
  chunks: Uint8Array[],
  d: bigint,
  p: bigint,
  q: bigint,
  n: bigint,
  nByteLen: number,
  onProgress?: (stage: string, progress: number) => void,
  dp?: bigint,
  dq?: bigint,
  qInv?: bigint,
): Promise<string> {
  if (!dp) dp = d % (p - 1n);
  if (!dq) dq = d % (q - 1n);
  if (!qInv) qInv = this.getPrivateKeyD(q, p);
  
  const decryptedChunks: Uint8Array[] = [];
  
  for (let i = 0; i < chunks.length; i++) {
    const chunk = chunks[i];
    const c = this.bytesToBigInt(chunk);
    
    const cp = c >= p ? c % p : c;
    const cq = c >= q ? c % q : c;
    
    const m1 = this.modExp(cp, dp, p);
    const m2 = this.modExp(cq, dq, q);
    
    let diff = m1 - m2;
    if (diff < 0n) diff += p;
    
    const h = (qInv * diff) % p;
    const m = m2 + h * q;
    
    // ← ここを修正！m が n より大きい場合は mod n する
    const mNormalized = m >= n ? m % n : m;
    
    // ← サイズも柔軟に
    let paddedMsg: Uint8Array;
    try {
      paddedMsg = this.bigintToUint8Array(mNormalized, nByteLen);
    } catch {
      // サイズ指定なしで変換
      paddedMsg = this.bigintToUint8Array(mNormalized);
      // nByteLen に合わせてパディング
      if (paddedMsg.length < nByteLen) {
        const temp = new Uint8Array(nByteLen);
        temp.set(paddedMsg, nByteLen - paddedMsg.length);
        paddedMsg = temp;
      }
    }
    
    try {
      const messageChunk = await this.oeapUnpad(paddedMsg, nByteLen, new Uint8Array(0));
      decryptedChunks.push(messageChunk);
    } catch {
      const filtered = paddedMsg.filter(byte => byte !== 0x00);
      decryptedChunks.push(new Uint8Array(filtered));
    }
    
    onProgress?.(
      `復号・ブロック処理中 (${i + 1}/${chunks.length})`,
      Math.floor(((i + 1) / chunks.length) * 100)
    );
  }
  
  const totalLength = decryptedChunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const combined = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of decryptedChunks) {
    combined.set(chunk, offset);
    offset += chunk.length;
  }
  
  return new TextDecoder().decode(combined);
}
  
  // Worker並列版
  private async decryptParallel(
    chunks: Uint8Array[],
    d: bigint,
    p: bigint,
    q: bigint,
    n: bigint,
    nByteLen: number,
    onProgress?: (stage: string, progress: number) => void,
    dp?: bigint,
    dq?: bigint,
    qInv?: bigint,
  ): Promise<string> {
    if (!dp) dp = d % (p - 1n);
    if (!dq) dq = d % (q - 1n);
    if (!qInv) qInv = this.getPrivateKeyD(q, p);
    
    const chunksPerWorker = Math.ceil(chunks.length / this.workerCount);
    
    // chunksをbase64文字列配列に変換
    const chunksB64 = chunks.map(chunk => btoa(String.fromCharCode(...chunk)));
    
    const promises = this.decryptWorkers.map((worker, idx) => {
      const start = idx * chunksPerWorker;
      const end = Math.min(start + chunksPerWorker, chunksB64.length);
      const workerChunks = chunksB64.slice(start, end);
      
      if (workerChunks.length === 0) return Promise.resolve([]);
      
      return new Promise<Uint8Array[]>((resolve) => {
        worker.onmessage = (event) => {
          // エラーチェック
          if (event.data.error) {
            console.error('❌ Worker内でエラー:', event.data.error);
            resolve([]);
            return;
          }
          
          if (!event.data.results) {
            console.error('❌ results が undefined!');
            resolve([]);
            return;
          }
          
          const base64Results: string[] = event.data.results;
          const uint8Results = base64Results.map(b64 => 
            Uint8Array.from(atob(b64), c => c.charCodeAt(0))
          );
          resolve(uint8Results);
        };
        
        worker.onerror = (err) => {
          console.error('❌ Workerエラー:', err);
          resolve([]);
        };
        
        worker.postMessage({
          chunks: workerChunks,
          d: d.toString(),
          p: p.toString(),
          q: q.toString(),
          dp: dp.toString(),
          dq: dq.toString(),
          qInv: qInv.toString(),
          nByteLen,
        });
      });
    });
    
    onProgress?.("並列復号中", 50);
    
    const results = await Promise.all(promises);
    
    const allChunks = results.flat();
    const totalLength = allChunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const combined = new Uint8Array(totalLength);
    
    let offset = 0;
    for (const chunk of allChunks) {
      combined.set(chunk, offset);
      offset += chunk.length;
    }
    
    onProgress?.("復号完了", 100);
    
    return new TextDecoder().decode(combined);
  }

  // PKCS#1 v1.5パディングを追加
// OpenSSL完全互換のRSA署名実装

private addPKCS1Padding(hash: Uint8Array, keyBits: number): bigint {
  // SHA-256のDER-encoded DigestInfo
  const digestInfo = new Uint8Array([
    0x30,
    0x31,
    0x30,
    0x0d,
    0x06,
    0x09,
    0x60,
    0x86,
    0x48,
    0x01,
    0x65,
    0x03,
    0x04,
    0x02,
    0x01,
    0x05,
    0x00,
    0x04,
    0x20,
    ...hash,
  ]);

  const tLen = digestInfo.length;
  const emLen = Math.floor((keyBits + 7) / 8);

  if (emLen < tLen + 11) {
    throw new Error("鍵サイズが小さすぎます");
  }

  // 0x00 || 0x01 || PS || 0x00 || T
  const ps = new Uint8Array(emLen - tLen - 3).fill(0xff);
  const em = new Uint8Array(emLen);
  em[0] = 0x00;
  em[1] = 0x01;
  em.set(ps, 2);
  em[emLen - tLen - 1] = 0x00;
  em.set(digestInfo, emLen - tLen);

  return this.bytesToBigInt(em);
}

// PKCS#1パディングを検証
private verifyPKCS1Padding(em: Uint8Array): Uint8Array | null {
  if (em.length < 11) return null;
  if (em[0] !== 0x00 || em[1] !== 0x01) return null;

  let i = 2;
  while (i < em.length && em[i] === 0xff) i++;

  if (i < 10 || em[i] !== 0x00) return null;

  const digestInfo = em.slice(i + 1);

  // DigestInfoの検証（SHA-256）
  if (digestInfo.length !== 51) return null;
  if (digestInfo[0] !== 0x30 || digestInfo[1] !== 0x31) return null;

  // ハッシュ値を抽出（最後の32バイト）
  return digestInfo.slice(19, 51);
}

// OpenSSL互換署名（PKCS#1 v1.5）
public async signStringToBase64(
  text: string,
  d: bigint,
  p: bigint,
  q: bigint,
  n: bigint,
  dp?: bigint,
  dq?: bigint,
  qInv?: bigint,
): Promise<string> {
  const msgBin = new TextEncoder().encode(text);
  const hashBin = await this.sha256(msgBin);

  const keyBits = this.bitLength(n);
  const keyBytes = Math.floor((keyBits + 7) / 8);
  const m = this.addPKCS1Padding(hashBin, keyBits);

  if (!dp) dp = d % (p - 1n);
  if (!dq) dq = d % (q - 1n);
  if (!qInv) qInv = this.getPrivateKeyD(q, p);

  const mp = m % p;
  const mq = m % q;

  const s1 = this.modExp(mp, dp, p);
  const s2 = this.modExp(mq, dq, q);

  let diff = s1 - s2;
  if (diff < 0n) diff += p;

  const h = (qInv * diff) % p;
  const s = s2 + h * q;

  // 【重要な修正】署名値を常に鍵サイズと同じバイト数にする
  return this.bytesToBase64(this.bigintToUint8Array(s, keyBytes));
}

// OpenSSL互換署名検証
public async verifyBase64Signature(
  text: string,
  b64Sig: string,
  e: bigint,
  n: bigint,
): Promise<boolean> {
  try {
    const sigBin = this.base64ToBytes(b64Sig);
    const s = this.bytesToBigInt(sigBin);

    // 署名値が n より小さいことを確認
    if (s >= n) return false;

    // 署名を検証（RSA公開鍵演算）
    const m = this.modExp(s, e, n);

    // パディングされたメッセージをバイト配列に変換
    const keyBits = this.bitLength(n);
    const keyBytes = Math.floor((keyBits + 7) / 8);
    const em = this.bigintToUint8Array(m, keyBytes);

    // PKCS#1パディングを検証してハッシュを抽出
    const extractedHash = this.verifyPKCS1Padding(em);
    if (!extractedHash) return false;

    // 実際のハッシュ値を計算
    const msgBin = new TextEncoder().encode(text);
    const hashBin = await this.sha256(msgBin);

    // ハッシュ値を比較
    if (extractedHash.length !== hashBin.length) return false;
    return extractedHash.every((byte, i) => byte === hashBin[i]);
  } catch {
    return false;
  }
}

  // bigintToUint8Arrayにサイズ指定版も追加

private bitLength(n: bigint): number {
  return n.toString(2).length;
}

// メインの振り分け関数
private modExp(base: bigint, exp: bigint, mod: bigint): bigint {
  // 指数が小さければバイナリ法（暗号化用）、大きければモンゴメリ（復号用）
  return exp < 1000000n 
    ? this.binaryModExp(base, exp, mod) 
    : this.montgomeryModExp(base, exp, mod);
}

// 追加：バイナリ法
private binaryModExp(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n;
  
  // 最初に base を mod 以下の正の数に収める
  let b = base % mod;
  if (b === 0n) return 0n; // baseがmodの倍数なら結果は常に0
  
  let res = 1n;
  let e = exp;

  while (e > 0n) {
    // 奇数判定をビット演算に（TS/JSのBigIntでも有効）
    if (e & 1n) {
      res = (res * b) % mod;
    }
    
    // e を半分にする
    e >>= 1n;
    
    // eが0になったら、これ以上 b の二乗（重い演算）は不要
    if (e === 0n) break;

    // ここが一番重い：BigIntの乗算＋剰余
    b = (b * b) % mod;
  }
  
  return res;
}

// 追加：マインさんの最強モンゴメリ法（中身はさっきのやつ）
private montgomeryModExp(base: bigint, exp: bigint, mod: bigint, k: number = 5): bigint {
  // ここにマインさんが持っていた（あるいは僕がさっき出した）
  // モンゴメリ＋スライディングウィンドウのロジックを入れます
  const modBits = BigInt(this.bitLength(mod));
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
  for (let i = 1; i < tableSize; i++) table[i] = reduce(table[i - 1] * baseBar2);

  let res = (1n << modBits) % mod;
  const expBits = this.bitLength(exp);
  let bitPos = expBits - 1;

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
  

  public parsePublicKeyPem(pem: string) {
    const base64 = pem.replace(/-----.*?-----|\s+/g, "");
    const der = this.base64ToBytes(base64);
    let offset = 0;

    const parseLength = (): number => {
      let len = der[offset++];
      if (len & 0x80) {
        const count = len & 0x7f;
        let val = 0;
        for (let i = 0; i < count; i++) {
          val = (val << 8) | der[offset++];
        }
        return val;
      }
      return len;
    };

    const integers: bigint[] = [];
    while (offset < der.length) {
      const tag = der[offset++];

      if (tag === 0x30 || tag === 0x03) {
        parseLength();
        if (tag === 0x03) offset++;
        continue;
      }

      if (tag === 0x02) {
        const len = parseLength();
        const bytes = der.subarray(offset, offset + len);
        integers.push(this.bytesToBigInt(bytes));
        offset += len;
      } else {
        const len = parseLength();
        offset += len;
      }
    }

    let n = 0n,
      e = 0n;
    for (const v of integers) {
      if (v > 65537n) n = v;
      else if (v === 65537n || v === 3n) e = v;
    }

    return { n, e };
  }

  public parsePrivateKeyPem(pem: string) {
    if (pem.includes("BEGIN OPENSSH PRIVATE KEY")) {
      return this.parseOpenSSH(pem);
    }

    const base64 = pem.replace(/-----.*?-----|\s+/g, "");
    const der = this.base64ToBytes(base64);
    let offset = 0;

    const parseLength = (): number => {
      let len = der[offset++];
      if (len & 0x80) {
        const count = len & 0x7f;
        let val = 0;
        for (let i = 0; i < count; i++) {
          val = (val << 8) | der[offset++];
        }
        return val;
      }
      return len;
    };

    const integers: bigint[] = [];
    while (offset < der.length) {
      const tag = der[offset++];

      if (tag === 0x30 || tag === 0x04) {
        parseLength();
        continue;
      }

      if (tag === 0x02) {
        const len = parseLength();
        const bytes = der.subarray(offset, offset + len);
        integers.push(this.bytesToBigInt(bytes));
        offset += len;
      } else {
        const len = parseLength();
        offset += len;
      }
    }

    const bigOnes = integers.filter((v) => v > 0n);

    return {
      n: bigOnes[0],
      e: bigOnes[1],
      d: bigOnes[2],
      p: bigOnes[3],
      q: bigOnes[4],
    };
  }

  private parseOpenSSH(pem: string) {
    const base64 = pem.replace(/-----.*?-----|\s+/g, "");
    const bin = this.base64ToBytes(base64);
    const view = new DataView(bin.buffer, bin.byteOffset, bin.byteLength);
    let pos = 0;

    const readBuffer = () => {
      const len = view.getUint32(pos);
      pos += 4;
      const data = bin.subarray(pos, pos + len);
      pos += len;
      return data;
    };

    pos += 15;
    readBuffer();
    readBuffer();
    readBuffer();
    const numKeys = view.getUint32(pos);
    pos += 4;
    readBuffer();

    const privBlob = readBuffer();
    const pView = new DataView(
      privBlob.buffer,
      privBlob.byteOffset,
      privBlob.byteLength,
    );
    let bPos = 0;

    const readBlobBuffer = () => {
      const len = pView.getUint32(bPos);
      bPos += 4;
      const data = privBlob.subarray(bPos, bPos + len);
      bPos += len;
      return data;
    };

    bPos += 8;
    readBlobBuffer();

    const n = this.bytesToBigInt(readBlobBuffer());
    const e = this.bytesToBigInt(readBlobBuffer());
    const d = this.bytesToBigInt(readBlobBuffer());
    const iqmp = this.bytesToBigInt(readBlobBuffer());
    const p = this.bytesToBigInt(readBlobBuffer());
    const q = this.bytesToBigInt(readBlobBuffer());

    return { n, e, d, p, q };
  }

  private bytesToBigInt(bytes: Uint8Array): bigint {
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

  public generateLargePrime(bits: number): bigint {
    const byteLen = bits / 8;
    const uint8 = new Uint8Array(byteLen);
    const min = 1n << BigInt(bits - 1);
    const e = 65537n;

    while (true) {
      globalThis.crypto.getRandomValues(uint8);
      let p = this.bytesToBigInt(uint8) | 1n | min;

      const remainders = new Int32Array(this.smallPrimes.length);
      for (let j = 0; j < this.smallPrimes.length; j++) {
        remainders[j] = Number(p % BigInt(this.smallPrimes[j]));
      }

      for (let step = 0; step < 2000; step++) {
        let isComposite = false;

        for (let j = 0; j < this.smallPrimes.length; j++) {
          if (remainders[j] === 0) {
            isComposite = true;
            break;
          }
        }

        if (!isComposite && (p - 1n) % e !== 0n) {
          if (this.isProbablyPrime(p, 1)) {
            if (this.isProbablyPrime(p, 4)) {
              return p;
            }
          }
        }

        p += 2n;
        for (let j = 0; j < this.smallPrimes.length; j++) {
          const pj = this.smallPrimes[j];
          let r = remainders[j] + 2;
          if (r >= pj) {
            r -= pj;
          }
          remainders[j] = r;
        }
      }
    }
  }

  public async generateRSAKeyPair(bits: number) {
    const e = 65537n;
    const half = bits / 2;

    const [p, q] = await Promise.all([
      this.generateLargePrimeWorker(half),
      this.generateLargePrimeWorker(half),
    ]);
    if (!p || !q) { 
      throw new Error("大きな素数の生成に失敗しました");
    }

    if (p === q) {
      return this.generateRSAKeyPair(bits);
    }

    const n = p * q;
    const phi = (p - 1n) * (q - 1n);

    if (this.gcd(e, phi) === 1n) {
      const d = this.getPrivateKeyD(e, phi);
      const dp = d % (p - 1n);
      const dq = d % (q - 1n);
      const qInv = this.getPrivateKeyD(q, p);

      return { n, e, d, p, q, phi, dp, dq, qInv };
    }

    return this.generateRSAKeyPair(bits);
  }

  private async generateLargePrimeWorker(bits: number): Promise<bigint> {
    return new Promise((resolve) => {
      let worker: Worker;
      try {
        worker = new Worker("./dist/mojyu-ru/prime-worker.js");
      } catch {
        return resolve(this.generateLargePrime(bits));
      }

      let resolved = false;

      worker.onmessage = (e) => {
        if (resolved) return;

        if (e.data.error) {
          resolved = true;
          worker.terminate();
          resolve(this.generateLargePrime(bits));
        } else {
          resolved = true;
          const prime = BigInt(e.data.prime);
          worker.terminate();
          resolve(prime);
        }
      };

      worker.onerror = () => {
        if (resolved) return;
        resolved = true;
        worker.terminate();
        resolve(this.generateLargePrime(bits));
      };

      worker.postMessage({ bits });
    });
  }

  public bigintToUint8Array(n: bigint, size?: number): Uint8Array {
    if (n === 0n) {
      return size ? new Uint8Array(size) : new Uint8Array([0]);
    }

    const bitLength = this.bitLength(n);
    const minByteLength = (bitLength + 7) >> 3;

    // sizeが指定されていない場合は既存の動作
    if (size === undefined) {
      const u8 = new Uint8Array(minByteLength);
      let tempN = n;
      for (let i = minByteLength - 1; i >= 0; i--) {
        u8[i] = Number(tempN & 0xffn);
        tempN >>= 8n;
      }
      return u8;
    }

    // sizeが指定されている場合
    if (minByteLength > size) {
      throw new Error(
        `数値が大きすぎます: ${minByteLength}バイト必要、${size}バイト指定`,
      );
    }

    const u8 = new Uint8Array(size); // 指定サイズで初期化（先頭はゼロパディング）
    let tempN = n;
    for (let i = size - 1; i >= size - minByteLength; i--) {
      u8[i] = Number(tempN & 0xffn);
      tempN >>= 8n;
    }
    return u8;
  }

  public exportToPem(
    n: bigint,
    e: bigint,
    d: bigint,
    p: bigint,
    q: bigint,
  ): string {
    const dmp1 = d % (p - 1n);
    const dmq1 = d % (q - 1n);
    const coeff = this.getPrivateKeyD(q, p);
    const values = [0n, n, e, d, p, q, dmp1, dmq1, coeff];
    const derElements = values.map((val) =>
      this.encodeDerInteger(this.bigintToUint8Array(val)),
    );

    const pkcs1Key = this.encodeDerSequence(derElements);

    const algorithmIdentifier = new Uint8Array([
      0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
      0x01, 0x05, 0x00,
    ]);

    const pkcs8Key = this.encodeDerSequence([
      this.encodeDerInteger(this.bigintToUint8Array(0n)),
      algorithmIdentifier,
      new Uint8Array([
        0x04,
        ...this.encodeDerLength(pkcs1Key.length),
        ...pkcs1Key,
      ]),
    ]);

    const base64 = this.bytesToBase64(pkcs8Key);
    const formattedBase64 = base64.match(/.{1,64}/g)?.join("\n");

    return `-----BEGIN PRIVATE KEY-----\n${formattedBase64}\n-----END PRIVATE KEY-----`;
  }

  public PublicKeyPem(n: bigint, e: bigint): string {
    const rsaPubKey = this.encodeDerSequence([
      this.encodeDerInteger(this.bigintToUint8Array(n)),
      this.encodeDerInteger(this.bigintToUint8Array(e)),
    ]);
    const algorithmIdentifier = new Uint8Array([
      0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
      0x01, 0x05, 0x00,
    ]);
    const spki = this.encodeDerSequence([
      algorithmIdentifier,
      this.encodeDerBitString(rsaPubKey),
    ]);
    const base64 = this.bytesToBase64(spki);
    return `-----BEGIN PUBLIC KEY-----\n${base64.match(/.{1,64}/g)?.join("\n")}\n-----END PUBLIC KEY-----`;
  }

  private bytesToBase64(bytes: Uint8Array): string {
    let binary = "";
    const len = bytes.length;
    const chunkSize = 8192;

    for (let i = 0; i < len; i += chunkSize) {
      const chunk = bytes.subarray(i, Math.min(i + chunkSize, len));
      binary += String.fromCharCode(...chunk);
    }
    return btoa(binary);
  }

  private base64ToBytes(b64: string): Uint8Array {
    const binString = atob(b64);
    const len = binString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binString.charCodeAt(i);
    }
    return bytes;
  }

  public getPrivateKeyD(e: bigint, phi: bigint): bigint {
    let r0 = phi,
      r1 = e;
    let x0 = 0n,
      x1 = 1n;

    while (r1 !== 0n) {
      const q = r0 / r1;
      const r = r0 - q * r1;
      r0 = r1;
      r1 = r;
      const tmp = x0 - q * x1;
      x0 = x1;
      x1 = tmp;
    }

    return x0 < 0n ? x0 + phi : x0;
  }

  public gcd(a: bigint, b: bigint): bigint {
    while (b !== 0n) {
      let t = b;
      b = a % b;
      a = t;
    }
    return a;
  }

  public rnd(n: bigint): bigint {
    const bitLength = this.bitLength(n);
    const byteLength = (bitLength + 7) >> 3;
    const uint8 = new Uint8Array(byteLength);

    while (true) {
      globalThis.crypto.getRandomValues(uint8);
      const num = this.bytesToBigInt(uint8) & ((1n << BigInt(bitLength)) - 1n);
      if (num > 0n && num < n) return num;
    }
  }

  public isProbablyPrime(n: bigint, k: number = 15): boolean {
    if (n <= 3n) return n > 1n;
    if (!(n & 1n)) return false;

    for (let j = 0; j < this.smallPrimes.length; j++) {
      const p = this.smallPrimes[j];
      if (n === BigInt(p)) return true;
      if (n < BigInt(p) * BigInt(p)) break;
      if (n % BigInt(p) === 0n) return false;
    }

    let d = n - 1n;
    let s = 0;
    while (!(d & 1n)) {
      d >>= 1n;
      s++;
    }

    const nm1 = n - 1n;

    const bases = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];

    for (let i = 0; i < k; i++) {
      const a = i < bases.length ? bases[i] : this.rnd(nm1);

      let x = this.modExp(a, d, n);

      if (x === 1n || x === nm1) continue;

      let composite = true;
      for (let r = 1; r < s; r++) {
        x = this.modExp(x, 2n, n);

        if (x === nm1) {
          composite = false;
          break;
        }
        if (x === 1n) return false;
      }

      if (composite) return false;
    }

    return true;
  }

  private encodeDerInteger(bytes: Uint8Array): Uint8Array {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) {
      start++;
    }
    const trimmedLen = bytes.length - start;

    const needsPadding = bytes[start] >= 0x80;
    const payloadLen = needsPadding ? trimmedLen + 1 : trimmedLen;

    const lenBytes = this.encodeDerLength(payloadLen);
    const result = new Uint8Array(1 + lenBytes.length + payloadLen);
    let offset = 0;

    result[offset++] = 0x02;
    result.set(lenBytes, offset);
    offset += lenBytes.length;

    if (needsPadding) {
      result[offset++] = 0x00;
    }

    result.set(bytes.subarray(start), offset);
    return result;
  }

  private encodeDerSequence(elements: Uint8Array[]): Uint8Array {
    const totalLength = elements.reduce((acc, el) => acc + el.length, 0);
    const body = new Uint8Array(totalLength);
    let offset = 0;
    for (const el of elements) {
      body.set(el, offset);
      offset += el.length;
    }

    const length = this.encodeDerLength(body.length);
    const res = new Uint8Array(1 + length.length + body.length);
    res[0] = 0x30;
    res.set(length, 1);
    res.set(body, 1 + length.length);
    return res;
  }

  private encodeDerBitString(bytes: Uint8Array): Uint8Array {
    return new Uint8Array([
      0x03,
      ...this.encodeDerLength(bytes.length + 1),
      0x00,
      ...bytes,
    ]);
  }

  private encodeDerLength(len: number): Uint8Array {
    if (len <= 127) return new Uint8Array([len]);

    let bytesNeeded = 0;
    if (len >= 0x1000000) bytesNeeded = 4;
    else if (len >= 0x10000) bytesNeeded = 3;
    else if (len >= 0x100) bytesNeeded = 2;
    else bytesNeeded = 1;

    const res = new Uint8Array(bytesNeeded + 1);
    res[0] = 0x80 | bytesNeeded;

    let t = len;
    for (let i = bytesNeeded; i >= 1; i--) {
      res[i] = t & 0xff;
      t >>= 8;
    }
    return res;
  }
}
function isinmu(isinmu: boolean) {
      if (isinmu) {
    const link = document.createElement("link");
    link.rel = "icon";
    link.href = "https://kazuhiro-tokumoto.github.io/rsa/img/yaju.jpg";
    link.type = "image/jpeg";
    document.head.appendChild(link);
    const title = document.createElement("title");
    title.textContent = "イ ン ム 暗 号 化 デ モ";
    document.head.appendChild(title);
  } else {
    const link = document.createElement("link");
    link.rel = "icon";
    link.href = "https://kazuhiro-tokumoto.github.io/rsa/img/rsa_icon.png";
    link.type = "image/png";
    document.head.appendChild(link);
    const title = document.createElement("title");
    title.textContent = "教科書的RSA暗号化デモ";
    document.head.appendChild(title);
  }
}
function createHeader(text: string, author: string, showHome: boolean) {
  const headerContainer = document.createElement('div');
  
  // className="flex flex-row border-b-[1px] w-full justify-center items-center mb-[2dvh]"
  headerContainer.style.cssText = `
    display: flex;
    flex-direction: row;
    border-bottom: 1px solid currentColor;
    width: 100%;
    justify-content: center;
    align-items: center;
    margin-bottom: 2dvh;
  `;

  if (showHome) {
    const homeLink = document.createElement('p');
    homeLink.textContent = 'ホームへ';
    
    // className="text-xl mb-[1dvh] justify-center items-center flex mr-[5dvh] cursor-pointer"
    homeLink.style.cssText = `
      font-size: 1.25rem;
      margin: 0;
      margin-bottom: 1dvh;
      margin-right: 5dvh;
      display: flex;
      justify-content: center;
      align-items: center;
      cursor: pointer;
    `;
    
    homeLink.onclick = () => {
      window.location.href = 'https://tools.shudo-physics.com/';
    };
    
    headerContainer.appendChild(homeLink);
  }

  const title = document.createElement('p');
  title.textContent = text;
  
  // className="text-3xl mb-[1dvh]"
  title.style.cssText = `
    font-size: 1.875rem;
    margin: 0;
    margin-bottom: 1dvh;
  `;
  
  headerContainer.appendChild(title);

  return headerContainer;
}
const inmuData = [
  {
    high: [
      "110弱でしょうねぇ",
      "14万3千円",
      "14万！？",
      "1万円くれたらしゃぶってあげるよ",
      "24でぇ～す",
      "24歳、学生です",
      "30分で、5万",
      "36…普通だな",
      "36、普通だな！",
      "3人に勝てるわけないだろ！",
      "3人は、どういう集まりなんだっけ？",
      "3人はどういう集まりなんだっけ",
      "3回だよ、3回",
      "Foo↑",
      "Foo↑気持ちぃ～",
      "KMR早くしろ～↑",
      "MUR早いっすね",
      "TARGET...CAPTURED...BODY SENSOR...",
      "YO！（日顕）",
      "あぁ^～、いいっすねぇ～",
      "あぁ＾～、いいっすねぇ～",
      "ああ逃れられない",
      "ああ逃れられない！",
      "ああ～いいっすね～",
      "あくしろよ",
      "あっ、おい待てぃ（江戸っ子）",
      "あっ、そうだ（唐突）",
      "あっそうだ",
      "あっそっかぁ",
      "あっ・・・（察し）",
      "あとその為の拳",
      "あのさぁ",
      "あのさぁ・・・",
      "あのさぁ・・・もうバックはいいから、フェラやってもらってさ、終わりで良いんじゃない？（棒読み）",
      "あほくさ",
      "ありがとナス",
      "ありますあります",
      "あ゛あ゛あ゛あ゛あ゛あ゛あ゛あ゛あ゛あ゛あ゛あ゛あ゛も゛う゛や゛だ゛あ゛あ゛あ゛あ゛あ゛あ゛あ゛あ゛あ゛あ゛あ゛あ゛あ゛あ゛！！！！！",
      "あーさっぱりした（皮肉）",
      "あーもう1回行ってくれ",
      "あーもうめちゃくちゃだよ",
      "あーもう一回いってくれ",
      "あーソレいいよ",
      "あ＾～もうおしっこ出ちゃいそう",
      "いいよ、来いよ",
      "いいよ！来いよ！胸にかけて胸に！",
      "いいゾ～これ",
      "いいゾ～コレ",
      "いきますよーいくいく",
      "いなりが入ってないやん",
      "いや、マジこれうんこ出、出ちゃいそうな勢いなんですけど、それは大丈夫なんですかね・・・",
      "いや～キツイっす",
      "う、羽毛・・・",
      "うまいぞフェラ（空気）",
      "うるせぇ！",
      "うれしい…うれしい…",
      "うん、おいしい",
      "うん、美味しい",
      "うんちして♡",
      "えっ、それは・・・（困惑）",
      "えっ、そんなん関係無いでしょ（正論）",
      "えっ山下公園行けばいいじゃん",
      "おいゴルァ",
      "おいヤメルルォ！",
      "おう、考えてやるよ",
      "おう、考えてやるよ（返すとは言ってない）",
      "おう打ってこい打ってこい",
      "おう早くしろよ",
      "おかのした",
      "おっ、そうだな",
      "おっ、大丈夫か大丈夫か？",
      "おっ、開いてんじゃ～ん！",
      "おっそうだな",
      "おっ大丈夫か大丈夫か",
      "おっ開いてんじゃ～ん",
      "おまたせ！アイスティーしかなかったけどいいかな？",
      "おまんこぉ",
      "お兄さん許して",
      "お前がしゃぶれよ",
      "お前ここ初めてか",
      "お前さっき俺らが着替えてるときチラチラ見てただろ",
      "お前の事が好きだったんだよ",
      "お前の事が好きだったんだよ！",
      "お前の自意識過剰なんじゃねえか？",
      "お前もしかして、あいつの事が好きなのか？（青春）",
      "お前らもよーく見とけよ。",
      "お前ノンケかよぉ",
      "お前一番態度悪いって言われてるぞ",
      "お前初めてかここ",
      "お金タダでいいから",
      "くっせえなお前",
      "こ↑こ↓",
      "こ、去年ですね",
      "こっちの事情も考えてよ（棒読み）",
      "この人頭おかしい",
      "この辺がセクシー、エロいっ！",
      "この辺にぃ、うまいラーメン屋の屋台、来てるらしいんすよ",
      "これはキツイですよ",
      "これは痛い",
      "これもうわかんねぇな",
      "こわいなーとづまりすとこ",
      "こわいなーとづまりスト4",
      "こんなんじゃ商品になんないよ",
      "こんなんじゃ商品になんないよ～（棒読み）",
      "こんなんじゃ商品になんねぇんだよ",
      "ご褒美なの",
      "しかなかったんだけどいいかな",
      "して、どうぞ",
      "してはいけない",
      "しゃぶってよ",
      "しゃぶってよ、怒ってんの？（棒読み）",
      "しゃぶらなきゃ撃つぞゴラァ！",
      "しゃぶれよ",
      "しょうがないね",
      "しょうがねえなぁ（悟空）",
      "じゃあまず、年齢を教えてくれるかな",
      "じゃあオラオラ来いよオラァ",
      "じゃあ今までのちかえしをたっぷりとさせてもらおうじゃないか",
      "じゃあ今までのちかえしをたっぷりとさせて貰おうじゃないか",
      "じゃあ俺、ギャラ貰って帰るから（棒読み）",
      "じゃけん夜行きましょうね",
      "じゃけん夜行きましょうね～",
      "すいませへぇぇ～ん",
      "すいませへぇぇ～ん！",
      "すいません許してください",
      "すいません許してください！何でもしますから！",
      "すっげえキツかったゾ～",
      "すっげえ白くなってる、はっきりわかんだね",
      "そう…(無関心)",
      "そう…（無関心）",
      "そうだよ(便乗)",
      "そうだよ（便乗）",
      "そう・・・（無関心）",
      "そのための右手",
      "その分は・・・ギャラ出すんで（棒読み）",
      "その為の右手",
      "それは君の錯覚だよぉ（能天気）",
      "それ一番言われてるから",
      "そんなことしたらパパに怒られちゃうだろ",
      "そんなことしちゃあダメだろ",
      "そんなことしなくていいから",
      "そんなことしなくていいから（良心）",
      "そんなんじゃ甘いよ",
      "そんなんじゃ虫も殺せねぇぞお前ら！",
      "たまげたな",
      "だいぶ溜まってんじゃんアゼルバイジャン",
      "だからこんなんじゃ商品になんねぇんだよ（棒読み）",
      "だからね、しょうがないね",
      "だから痛てぇっつってんじゃねえかよ（棒読み）",
      "だと思うんですけど",
      "ちゃんと2本加え入れろ～？",
      "ちゃんと二本咥え入れろ",
      "ちょっと待って！何これ？",
      "ちょっと歯ぁ当たんよ",
      "ちょっと歯当たんよ～（指摘）",
      "つっかえ",
      "てめぇら俺のおもちゃでいいんだ上等だろ",
      "で、出ますよ",
      "とぼけちゃってぇ・・・",
      "どういう集まりなんだっけ",
      "どうすっかな～",
      "どうすっかな～俺もな～",
      "ないです",
      "なめてんじゃねーぞ",
      "なんか必要ねぇんだよ",
      "なんか犯されてるよ",
      "なんか芸術的",
      "なんか足んねぇよなぁ",
      "なんだお前根性なしだな",
      "なんだお前根性無しだな",
      "なんだこのオッサン！？（驚愕）",
      "なんだよ…お前のケツ、ガバガバじゃねえかよ",
      "なんだよお前のケツガバガバじゃねえかよ",
      "なんてことを・・・(憤怒)",
      "なんで見る必要なんかあるんですか",
      "なんで見る必要なんかあるんですか（正論）",
      "なんのこったよ(すっとぼけ)",
      "ぬわあああああああああああん疲れたもおおおおおおおおおおおおおおおん",
      "ぬわあああああんメタもおおおおおおおん",
      "ぬわあああああん疲れたもおおおおおおおん",
      "ぬわああん疲れたもおおおおおおん",
      "ねねねね～、サーフィンって楽しい？",
      "はぁ～～～（クソデカため息）",
      "はぇ～すっごいおっきい",
      "はえ＾～すっごい大きい・・・",
      "はえ～",
      "はっきりわかんだね",
      "はーい、よーいスタート",
      "はーい、よーいスタート（棒読み）",
      "はーつっかえ",
      "は？（困惑）",
      "は？（威圧）",
      "ひでしね",
      "ふざけんじゃねぇよお前これどうしてくれんだよ！",
      "ふざけんな！(声だけ迫真)",
      "ふたいたい",
      "ふたいたいは・・・ボクサー型の・・・",
      "ふといちんぽがおまんこにはいっちゃう",
      "ぶち込んでやるぜ",
      "へええっ！？ホッ、ホナニーですかぁ！？",
      "ほらいくどー",
      "ほんとひで",
      "ほんへ",
      "ぼくひで",
      "ま、多少はね",
      "ま、多少はね？",
      "まあ、多少はね",
      "まずいですよ",
      "まずいですよ！",
      "まずうちさぁ・・・屋上・・・あんだけど、焼いてかない？",
      "まずウチさぁ",
      "また君か壊れるなぁ",
      "まーだ時間掛かりそうですかね～？",
      "もうこっから出れないんだよ",
      "もう十分堪能したよ",
      "もう始まってる",
      "もう始まってる！",
      "もう生きて帰れねぇな",
      "もう許せるぞ",
      "もう許せるぞオイ",
      "もっと舌使って舌使って",
      "やだよ（即答）",
      "やったぜ",
      "やっちゃうよ",
      "やっちゃうよ？やっちゃうよ！？",
      "やっぱり僕は・・・王道を往く、ソープ系ですかね",
      "やっぱり壊れてるじゃないか（憤怒）",
      "やっぱ好きなんすねぇ",
      "やべぇよ…やべぇよ…",
      "やべぇよ・・・やべぇよ・・・",
      "やべえよ",
      "やめたくなりますよ～部活～",
      "やめちくり",
      "やめちくり～",
      "やめてくれよ",
      "やめてくれよ・・・（絶望）",
      "やめてさしあげろ",
      "やめろぉ（建前）ナイスゥ（本音）",
      "やめろォ",
      "やめろォ（建前）ナイスゥ（本音）",
      "やりますねぇ",
      "やりますねぇ！",
      "やれば返して頂けるんですか",
      "ゆるして",
      "よし、じゃあブチ込んでやるぜ",
      "よし！じゃあぶち込んでやるぜ！",
      "よーく見とけよ",
      "わかったわかったダイエー",
      "わかるわかる(タメ口)",
      "わかる？この罪の重さ",
      "んにゃぴ",
      "んまぁそう…よく分かんなかったです",
      "ん？今なんでもするって言ったよね？",
      "ん？今何でもするって言ったよね？",
      "アッー！",
      "アツゥイ",
      "アツゥイ！",
      "イキますよ～ｲｸｲｸ・・・",
      "イキスギィ",
      "イキスギィ！",
      "イグッ",
      "ウッソだろ",
      "オッスお願いしまーす",
      "オッスお願いしま～す",
      "オナシャス",
      "オフッ",
      "カスが効かねぇんだよ（無敵）",
      "カットしろ",
      "キモティカ",
      "キモティ＝ダロ",
      "ギャラもらって帰るから",
      "クチアケーナ・ホラ",
      "クビだクビだクビだ！",
      "クルルァ",
      "ケツとかは・・・勘弁して下さいね（棒読み）",
      "ケツの穴舐めろ（鬼畜）",
      "ココアライオン",
      "サッー！（迫真）",
      "シュバルゴ！",
      "ジュージューになるまで",
      "ステロイドハゲ",
      "センセンシャル",
      "ターミナルさん",
      "ダイナマイッ",
      "ダイナモ感覚",
      "ダメみたいですね（諦観）",
      "デデドン",
      "ドジョウと俺のさ、子供ができたらどうする",
      "ドロヘドロ！（名作）",
      "ナイスゥ",
      "ナオキです",
      "ヌッ！",
      "ハイ, ヨロシクゥ！",
      "ハッ…ハッ…アッー！アーツィ！",
      "バラマキされそうで怖いっすね",
      "ビール！ビール！",
      "ファッ！？",
      "フゥー↑気持ちいい～",
      "ブッチッパ",
      "ブッチッパ！",
      "ホナニー",
      "ホモのくせによぉ",
      "ホラ、見ろよ見ろよ",
      "ホラホラホラホラ",
      "ホラホラホラホラ（鬼畜）",
      "マッチョして♡",
      "ミスが多すぎんだよね、それ一番言われてるから",
      "ムチ痛いのは分かってんだよ",
      "ヨツンヴァイン",
      "ライダー助けて",
      "ラグビーってなんだよ",
      "ンアッー",
      "ンアッー！",
      "ンギモッヂイイ",
      "乳首感じるんでしたよね",
      "二度とこの世界にいられないようにしてやる",
      "人間の屑",
      "人間の屑がこの野郎",
      "人間の屑がこの野郎・・・",
      "人間の鑑",
      "今何でもするって",
      "今日は、アドルフ・アイヒマンが逮捕された日なんですよ(暗黒微笑)",
      "以上",
      "何か足んねぇよなぁ？",
      "何がしゃぶれだぁ",
      "何が違うのか私には理解に苦しむね",
      "何だお前根性無しだな（棒読み）",
      "何だお前（素）",
      "何でもしますから",
      "何やってんだあいつら・・・",
      "俺もやったんだからさ",
      "俺もやったんだからさ（嫌々）",
      "俺も仲間に入れてくれよ～（ﾏｼﾞｷﾁｽﾏｲﾙ）",
      "俺も後から洗ってくれよな～頼むよ～",
      "僕は違います",
      "僕は馬鹿じゃない",
      "先生がビンビンでいらっしゃるよ、咥えて差し上げろ（名言）",
      "先輩コイツ玉とか舐め出しましたよ、やっぱ好きなんすね～",
      "先輩！？何してんすか、やめてくださいよ本当に！",
      "入って、どうぞ",
      "六尺、サポーターになって、H、しよう",
      "冗談はよしてくれ",
      "冷えてるか～？",
      "出、出ますよ・・・",
      "出そうと思えば（王者の風格）",
      "出ますよ～今日は～",
      "勃ってきちゃったよ・・・",
      "動くと当たらないだろ",
      "動物裁判だ",
      "喉渇いた…喉渇かない",
      "喉渇か・・・喉渇かない？",
      "嘘つけ絶対",
      "嘘つけ絶対見てたゾ",
      "土下座しろこの野郎",
      "堕ちろ",
      "外してんじゃねぇよバァカ",
      "多分変態だと思うんですけど",
      "多分変態だと思うんですけど（名推理）",
      "大丈夫だって安心しろよ",
      "大丈夫っすよバッチェ冷えてますよ",
      "大会近いからね、しょうがないね",
      "天の喝采～人として～",
      "好きッス",
      "嫌いじゃないけど好きじゃないよ",
      "嬉しいダルルォ！？",
      "子供のホモは観るかもしれない",
      "小並感",
      "小学生並の感想",
      "小生やだ",
      "屋上あんだけど",
      "当たり前だよなぁ",
      "当たり前だよなぁ？",
      "彼女とか、いらっしゃらないんですか？",
      "微レ存",
      "恥ずかしくないのかよ",
      "悔い改めて",
      "情けない格好、恥ずかしくないの",
      "感じるんでしたよね",
      "拡がりそうです",
      "早く帰って宿題しなきゃ",
      "暴れるなよ・・・暴れるな・・・",
      "暴れんなよ",
      "最後が気持ちよかった",
      "最後が気持ち良かった（小学生並みの感想）",
      "最後の一発くれてやるよ",
      "本気で怒らせちゃったね",
      "殺されてぇかお前",
      "気持ち良いか～KMR～",
      "流行らせコラ",
      "流行らせコラ！",
      "淫夢",
      "溜まってんなあおい",
      "溺れる！溺れる！",
      "焼いてかない",
      "王道を征く",
      "生きてるゥ",
      "痛いですね",
      "痛いですね・・・これは痛い・・・",
      "痛いんだよおおおおおおおおおおおお",
      "白菜かけますね",
      "白菜かけますね～",
      "皆解散",
      "知ｗらｗなｗいｗよｗ",
      "硬くなってんぜ",
      "硬くなってんぜ？",
      "窓際行って…シコれ",
      "窓際行って・・・シコれ（棒読み）",
      "笑っちゃうんすよね",
      "精神状態おかしいよ",
      "終わり",
      "終わりでいいんじゃない",
      "胸に",
      "胸にかけて",
      "腹減ったなぁ",
      "自分、指いいすか",
      "自分から入っていくのか",
      "自分の高校ではぁ～罰ゲームでぇ～公開オナニーってのがあったんすよ",
      "自分の高校では罰ゲームでぇ、公開オナニーってのがあったんですけど・・・",
      "良いだろお前成人の日だぞ（意味不明）",
      "菅野美穂（意味不明）",
      "行きませんか？行きましょうよ",
      "見える見える",
      "見たけりゃ見せてやるよ",
      "見たけりゃ見せてやるよ（震え声）",
      "見てないでこっち来て、お前も入れてみろよ",
      "見とけよ",
      "見とけよ見とけよ",
      "見とけよ見とけよ～",
      "見ろよ見ろよ",
      "訴訟も辞さない",
      "誰だよ、お前の彼か？",
      "調子こいてんじゃねえぞこの野郎",
      "調子こいてんじゃねーぞコノヤロー",
      "警察だ！（インパルス板倉）",
      "辞めたくなりますよ",
      "返すとは言ってない",
      "迫真",
      "違うだろ",
      "野獣先輩",
      "野球か何か？",
      "金！暴力！SEX！",
      "閉廷",
      "降りろ！免許もってんのか",
      "頭にきますよ",
      "頭に来ますよ～",
      "馬鹿野郎お前俺は勝つぞお前",
      "馬鹿野郎お前俺は勝つぞお前（天下無双）",
      "（返すとは言っていない）",
      "＾～",
      "ｱ゛↑ｱ゛↑ｱ゛↑ｱ゛↑ｱ゛↑ ｱｰｲｸｯ･･･",
      "ｱｰｲｷｿ",
      "ｱｰﾂﾒﾀｲ",
      "ｳｨﾋ!",
      "ｳｰﾝ",
      "ｳﾞｫｰ・・・",
      "ｸｫｸｫｱ･･･",
      "ﾁｶﾚﾀ・・・（小声）",
      "ﾎﾟｯﾁｬﾏ・・・",
      "ﾝｷﾞﾓﾁﾞｨｨｨ！！",
      "ﾝｷﾞﾓﾁﾞイイ",
      "ジラーチっす",
      "よろしくお願いさしすせそ",
      "ダルルォ",
    ],
    mid: [
      "19",
      "24",
      "114",
      "334",
      "364",
      "514",
      "810",
      "893",
      "931",
      "14万3千円",
      "143000",
      "(",
      ")",
      "ｷｿ",
      "アイスティー",
      "スギィ",
      "オォン",
      "アォン",
      "おまたせ",
      "菅野美穂",
      "悔い改めて",
      "エロいっ",
      "じゃけん",
      "ましょうね",
      "学生です",
      "どうぞ",
      "過ぎィ",
      "だからね",
      "しょうがないね",
      "ちょっと",
      "ないです",
      "ヌッ",
      "ぬわ",
      "かけますね",
      "Foo",
      "ファッ",
      "ふたいたいは",
      "ホラホラ",
      "多少はね",
      "見とけよ",
      "何してんすか",
      "止めて下さいよホントに",
      "早くしろ",
      "お前さっき俺",
      "チラチラ",
      "だったゾ",
      "そうだよ",
      "だゾ",
      "ウッソだろお前",
      "うるせぇ！",
      "だルルォ",
      "腹減ったなぁ",
      "冷えてるか",
      "アッー",
      "自分、",
      "いいっすか",
      "力抜けよ",
      "だなぁ",
      "やだよ",
      "なんじゃ",
      "してさ",
      "じゃじゃあ俺",
      "恥ずかしくないの",
      "窓際行って",
      "あ゛",
      "痛いんだよ",
      "ヴォエ",
      "溺れる",
      "怒られちゃうだろ",
      "しなきゃ",
      "ひで",
      "ほんとぉ",
      "やだ",
      "小生",
      "ライダー",
      "助けて",
      "えぇ…",
      "当たらないだろ",
      "のこと",
      "できましたか",
      "突っ込め",
      "ちたな",
      "かしこまり",
      "悲しいなぁ",
      "金！暴力！SEX！",
      "金!暴力!SEX!",
      "彼女とか、いらっしゃらないんですか",
      "髪なんか必要ねぇんだよ",
      "菅 野 美 穂",
      "汚ねえケツだなぁ",
      "気持ちいいって言ってみろ",
      "今日は逆さ吊り、鞭攻めをしよう",
      "for iPhone",
      "しなきゃ",
      "落ちたねぇ",
      "落ちましたね",
      "めちゃくちゃだよ",
      "あっ",
      "いかんのか",
      "いいだろお前",
      "インテル長友",
      "うせやろ",
      "うるせぇ",
      "ｳﾚｼｲ",
      "エンジン全開",
      "って言われてるぞ",
      "おかしいよ",
      "ホモ",
      "閉廷",
      "解散解散",
      "かな",
      "か何か",
      "ガバガバ",
      "きしょい",
      "クッソ",
      "警察だ",
      "こいついつも",
      "してんな",
      "こマ",
      "ですねぇ",
      "普通だな",
      "してはいけない",
      "死のうか",
      "初心者の",
      "そう・・・",
      "そんなことし",
      "ヘーキヘーキ",
      "いい加減にしろ",
      "つよそう",
      "ってなんだよ",
      "ですけどぉ",
      "なんですがそれは",
      "ナンボなん",
      "は？",
      "は?",
      "つっかえ",
      "みたいなもんやし",
      "また君か",
      "申し訳ないが",
      "申し訳無いが",
      "クソデカ",
      "小並感",
      "とは言って",
      "田所",
      "浩二",
      "遠野",
      "三浦",
      "木村",
      "拓也",
      "14万",
      "いなり",
      "ちょっと待って",
      "野獣",
      "先輩",
      "の裏技",
      "辞めたら",
      "やめたら",
      "中野くん",
      "料理を",
      "最高やな",
      "焼いてかない",
      "ああ＾～",
      "あーつまんねー",
      "（カルマ）",
      "(カルマ)",
      "(察し)",
      "あっ、これかぁ",
      "アメフトォ",
      "アメフト部",
      "いいねぇー",
      "（小声）",
      "(小声)",
      "(驚愕)",
      "（驚愕）",
      "(提案)",
      "（提案）",
      "ｸｩｰﾝ",
      "(戒め)",
      "（戒め）",
      "縛らなきゃ",
      "（使命感）",
      "(使命感)",
      "（困惑）",
      "(困惑)",
      "(無関心)",
      "（無関心）",
      "（名推理）",
      "(名推理)",
      "チカレタ",
      "冷えてるか",
      "（半ギレ）",
      "(半ギレ)",
      "ほんとぉ",
      "まずいですよ",
      "遠野",
      "免許証返してください",
      "もう始まってる",
      "やめてくれよ…",
      "(絶望)",
      "（絶望）",
      "（建前）",
      "(建前)",
      "(本音)",
      "（本音）",
      "(哲学)",
      "（哲学）",
      "（直球）",
      "(直球)",
      "入ってないやん",
      "ジラーチ",
    ],
  },
];
 const privacyWords = [
  // ============================================================
  // 基本的個人情報
  // ============================================================
  "名前", "氏名", "フルネーム", "本名", "苗字", "名字", "姓", "名", "ニックネーム", "あだ名", "通称", "芸名", "ペンネーム",
  "name", "fullname", "firstname", "lastname", "nickname", "realname", "alias",
  
  "住所", "自宅", "実家", "居住地", "所在地", "勤務先", "職場", "学校", "通学先", "下宿", "寮", "シェアハウス",
  "address", "home", "residence", "location", "workplace", "dwelling",
  
  "電話番号", "電話", "携帯", "スマホ", "固定電話", "TEL", "tel", "phone", "mobile", "cellular", "telephone", "fax", "ファックス",
  
  "誕生日", "生年月日", "年齢", "何歳", "生まれ", "birthday", "birth", "age", "birthdate", "born", "dob",
  
  // ============================================================
  // 開示・露出関連の徹底網羅
  // ============================================================
  "開示", "かいじ", "カイジ", "kaiji", "KAIJI", "Kaiji", "kaizi", "KAIZI", "Kaizi", "Кайдзи",
  "disclosure", "reveal", "expose", "情報公開", "公表", "発表",
  "晒", "晒す", "さら", "さらす", "サラ", "サラす", "バラす", "ばらす", "バラ", "ばら",
  "漏らす", "もらす", "漏洩", "流出", "リーク", "leak", "leaked", "暴露", "ばくろ",
  "特定", "とくてい", "身バレ", "みばれ", "身元", "identify", "identification", "dox", "doxx", "doxing", "doxxing",
  "公開", "こうかい", "見せる", "教える", "伝える", "知らせる", "通知", "共有",
  "アップロード", "投稿", "ポスト", "シェア", "share", "publish", "post", "upload", "display", "broadcast",
  
  // ============================================================
  // 露出・プライバシー侵害関連
  // ============================================================
  "露出", "ろしゅつ", "exposure", "公にする", "表に出す", "明かす", "あかす",
  "内部情報", "内部告発", "whistle", "whistleblower", "insider",
  "盗撮", "盗聴", "隠し撮り", "覗き", "のぞき", "surveillance", "spy", "stalk", "stalking", "ストーカー",
  
  // ============================================================
  // 都道府県（完全版）
  // ============================================================
  "都道府県", "都", "道", "府", "県", "市", "区", "町", "村", "郡", "政令指定都市",
  
  // 北海道・東北
  "北海道", "ほっかいどう", "hokkaido", "札幌", "さっぽろ", "sapporo", "函館", "旭川", "釧路", "帯広",
  "青森", "あおもり", "aomori", "弘前", "八戸",
  "岩手", "いわて", "iwate", "盛岡", "もりおか",
  "宮城", "みやぎ", "miyagi", "仙台", "せんだい", "sendai", "石巻",
  "秋田", "あきた", "akita",
  "山形", "やまがた", "yamagata", "米沢", "鶴岡", "酒田",
  "福島", "ふくしま", "fukushima", "郡山", "いわき", "会津",
  
  // 関東
  "茨城", "いばらき", "いばらぎ", "ibaraki", "水戸", "みと", "つくば", "筑波",
  "栃木", "とちぎ", "tochigi", "宇都宮", "うつのみや",
  "群馬", "ぐんま", "gunma", "前橋", "まえばし", "高崎", "たかさき",
  "埼玉", "さいたま", "saitama", "浦和", "大宮", "川口", "川越", "所沢",
  "千葉", "ちば", "chiba", "船橋", "松戸", "柏", "市川",
  "東京", "とうきょう", "tokyo", "新宿", "渋谷", "池袋", "上野", "品川", "六本木", "銀座", "秋葉原", "原宿", "表参道",
  "世田谷", "杉並", "練馬", "大田", "江戸川", "足立", "葛飾", "板橋", "江東", "墨田", "台東", "荒川", "北", "中野", "豊島",
  "港", "目黒", "文京", "中央", "千代田",
  "23区", "多摩", "八王子", "町田", "立川", "吉祥寺",
  "神奈川", "かながわ", "kanagawa", "横浜", "よこはま", "yokohama", "川崎", "かわさき", "相模原", "藤沢", "横須賀", "鎌倉",
  
  // 中部
  "新潟", "にいがた", "niigata", "長岡",
  "富山", "とやま", "toyama", "高岡",
  "石川", "いしかわ", "ishikawa", "金沢", "かなざわ", "kanazawa",
  "福井", "ふくい", "fukui", "敦賀",
  "山梨", "やまなし", "yamanashi", "甲府", "こうふ",
  "長野", "ながの", "nagano", "松本", "まつもと", "上田", "軽井沢",
  "岐阜", "ぎふ", "gifu", "高山", "多治見",
  "静岡", "しずおか", "shizuoka", "浜松", "はままつ", "hamamatsu", "沼津", "富士", "熱海",
  "愛知", "あいち", "aichi", "名古屋", "なごや", "nagoya", "豊田", "岡崎", "一宮", "豊橋",
  
  // 近畿
  "三重", "みえ", "mie", "津", "四日市",
  "滋賀", "しが", "shiga", "大津", "おおつ", "彦根",
  "京都", "きょうと", "kyoto", "宇治", "祇園", "嵐山",
  "大阪", "おおさか", "osaka", "梅田", "難波", "なんば", "心斎橋", "天王寺", "堺", "さかい", "吹田", "高槻", "枚方",
  "兵庫", "ひょうご", "hyogo", "神戸", "こうべ", "kobe", "姫路", "西宮", "尼崎", "明石", "芦屋", "宝塚",
  "奈良", "なら", "nara",
  "和歌山", "わかやま", "wakayama", "田辺", "白浜",
  
  // 中国
  "鳥取", "とっとり", "tottori", "米子",
  "島根", "しまね", "shimane", "松江", "まつえ", "出雲", "いずも",
  "岡山", "おかやま", "okayama", "倉敷", "くらしき",
  "広島", "ひろしま", "hiroshima", "福山", "呉", "くれ",
  "山口", "やまぐち", "yamaguchi", "下関", "しものせき", "宇部", "岩国",
  
  // 四国
  "徳島", "とくしま", "tokushima", "鳴門",
  "香川", "かがわ", "kagawa", "高松", "たかまつ",
  "愛媛", "えひめ", "ehime", "松山", "まつやま", "今治",
  "高知", "こうち", "kochi",
  
  // 九州・沖縄
  "福岡", "ふくおか", "fukuoka", "博多", "はかた", "hakata", "北九州", "きたきゅうしゅう", "久留米", "飯塚", "大牟田",
  "佐賀", "さが", "saga", "唐津", "鳥栖",
  "長崎", "ながさき", "nagasaki", "佐世保", "させぼ",
  "熊本", "くまもと", "kumamoto", "八代",
  "大分", "おおいた", "oita", "別府", "べっぷ",
  "宮崎", "みやざき", "miyazaki", "都城",
  "鹿児島", "かごしま", "kagoshima", "鹿屋", "霧島",
  "沖縄", "おきなわ", "okinawa", "那覇", "なは", "naha", "宜野湾", "浦添", "名護", "石垣",
  
  "ken", "pref", "prefecture", "city", "ward", "town", "village", "shi", "ku", "machi", "mura",
  
  // ============================================================
  // 住所詳細・建物
  // ============================================================
  "番地", "ばんち", "丁目", "ちょうめ", "号", "番", "の", "-",
  "建物名", "ビル", "マンション", "アパート", "ハイツ", "コーポ", "メゾン", "レジデンス", "パレス", "ヴィラ",
  "タワー", "プラザ", "スクエア", "テラス", "ガーデン", "コート", "ハウス", "ホーム",
  "部屋番号", "号室", "室", "階", "F", "building", "apartment", "room", "floor",
  "address", "jusho", "地図", "map", "マップ", "近く", "付近", "周辺", "最寄り", "駅",
  
  // ============================================================
  // 郵便番号・位置情報
  // ============================================================
  "郵便番号", "〒", "ポスト", "ゆうびん", "yubin", "zipcode", "postcode", "postal", "zip",
  "位置情報", "現在地", "居場所", "座標", "緯度", "経度", "GPS", "location", "place",
  "geolocation", "coordinates", "latitude", "longitude", "lat", "lon", "lng",
  "ジオタグ", "geotag", "位置", "場所", "チェックイン", "checkin",
  
  // ============================================================
  // 連絡先・メール
  // ============================================================
  "メール", "メールアドレス", "アドレス", "メルアド", "Eメール", "電子メール",
  "mail", "email", "e-mail", "address", "mail address", "email address",
  "gmail", "Gmail", "yahoo", "Yahoo", "outlook", "Outlook", "hotmail", "icloud", "docomo", "au", "softbank",
  "@", "ドメイン", "domain", ".com", ".jp", ".net", ".org",
  
  // ============================================================
  // SNS・メッセンジャー（超網羅版）
  // ============================================================
  // LINE
  "LINE", "ライン", "らいん", "line", "LINE ID", "ラインID", "QRコード", "QR", "友だち追加", "友達追加",
  
  // Twitter/X
  "Twitter", "ツイッター", "ついったー", "twitter", "X", "エックス", "@", "アット", "ツイート", "tweet",
  "リツイート", "RT", "DM", "フォロー", "フォロワー", "follower", "following",
  
  // Instagram
  "Instagram", "インスタ", "インスタグラム", "いんすた", "instagram", "insta", "IG", "ストーリー", "story", "リール", "reel",
  
  // Facebook
  "Facebook", "フェイスブック", "facebook", "FB", "messenger", "メッセンジャー",
  
  // TikTok
  "TikTok", "ティックトック", "tiktok", "ティクトク", "チクタク",
  
  // Discord
  "Discord", "ディスコード", "discord", "ディスコ", "サーバー", "server", "VC", "ボイチャ",
  
  // Skype
  "Skype", "スカイプ", "skype", "スカイプID",
  
  // Telegram
  "Telegram", "テレグラム", "telegram",
  
  // WhatsApp
  "WhatsApp", "ワッツアップ", "whatsapp",
  
  // Slack
  "Slack", "スラック", "slack", "ワークスペース", "workspace", "チャンネル", "channel",
  
  // その他SNS・コミュニケーションツール
  "YouTube", "ユーチューブ", "youtube", "チャンネル",
  "Twitch", "ツイッチ", "twitch", "配信",
  "Reddit", "レディット", "reddit",
  "Pinterest", "ピンタレスト", "pinterest",
  "LinkedIn", "リンクトイン", "linkedin",
  "Snapchat", "スナップチャット", "snapchat",
  "WeChat", "微信", "wechat",
  "KakaoTalk", "カカオトーク", "kakao",
  "Viber", "バイバー", "viber",
  "Signal", "シグナル", "signal",
  "Teams", "チームズ", "teams", "Microsoft Teams",
  "Zoom", "ズーム", "zoom", "ミーティングID",
  "Google Meet", "グーグルミート", "meet",
  "Clubhouse", "クラブハウス", "clubhouse",
  "mixi", "ミクシィ", "みくしぃ",
  "GREE", "グリー",
  "Mobage", "モバゲー",
  "アメブロ", "ameba", "アメーバ",
  "note", "ノート",
  "Pixiv", "ピクシブ", "pixiv",
  "ニコニコ", "ニコ動", "niconico", "nico",
  "はてな", "hatena", "はてなブックマーク",
  
  // ゲーム・配信プラットフォーム
  "Steam", "スチーム", "steam", "Steam ID",
  "PlayStation", "プレステ", "PSN", "PS", "playstation",
  "Xbox", "エックスボックス", "xbox", "ゲーマータグ", "gamertag",
  "Nintendo", "任天堂", "nintendo", "Switch", "スイッチ", "フレンドコード",
  "Epic Games", "エピック", "epic",
  "Origin", "オリジン", "origin",
  "Battle.net", "バトルネット", "battlenet",
  "Riot", "ライアット", "riot",
  
  // SNS一般用語
  "SNS", "ソーシャル", "social", "social media", "ソーシャルネットワーク",
  "プロフィール", "profile", "bio", "プロフ", "自己紹介",
  "アカウント", "アカウント名", "account", "username", "ユーザー名", "ID", "アイディー", "userid",
  "ハンドル", "ハンドルネーム", "handle",
  "DM", "ダイレクトメッセージ", "direct message", "メッセージ", "message",
  "投稿", "post", "ポスト", "コメント", "comment", "リプライ", "reply", "返信",
  "フォロー", "follow", "フォロワー", "follower", "フォロー中", "following",
  "いいね", "like", "ライク", "お気に入り", "favorite", "ふぁぼ", "ファボ",
  "シェア", "share", "リツイート", "retweet", "RT",
  "ブロック", "block", "ミュート", "mute", "通報", "report",
  "鍵垢", "鍵アカ", "裏垢", "サブ垢", "サブアカ", "本垢",
  
  // ============================================================
  // アカウント・認証情報
  // ============================================================
  "ログイン", "login", "log in", "sign in", "サインイン", "ログオン",
  "パスワード", "パス", "暗証番号", "PIN", "ピン", "合言葉", "秘密の質問", "答え",
  "password", "pass", "pw", "pwd", "passphrase", "passcode", "pin", "secret question", "security question",
  "認証", "二段階認証", "2段階認証", "二要素認証", "多要素認証", "2FA", "MFA",
  "ワンタイムパスワード", "OTP", "トークン", "token", "認証コード", "verification code",
  "authentication", "verification", "verify", "セキュリティキー", "security key",
  "生体認証", "biometric", "指紋", "顔認証", "Face ID", "Touch ID", "虹彩認証",
  "バックアップコード", "recovery code", "リカバリーコード",
  "秘密鍵", "公開鍵", "private key", "public key", "API key", "APIキー", "アクセストークン", "access token",
  
  // ============================================================
  // ネットワーク・デバイス情報
  // ============================================================
  "IPアドレス", "IP", "アイピー", "ipaddress", "ip address", "グローバルIP", "ローカルIP", "プライベートIP",
  "MACアドレス", "MAC", "mac address", "物理アドレス",
  "ホスト名", "hostname", "ドメイン", "domain", "サブドメイン", "subdomain",
  "DNS", "ディーエヌエス",
  "ポート", "port", "ポート番号",
  "プロバイダ", "ISP", "回線", "インターネット", "internet", "ネット", "net",
  "Wi-Fi", "WiFi", "無線LAN", "SSID", "ネットワーク名", "パスワード", "暗号化キー",
  "ルーター", "router", "モデム", "modem", "アクセスポイント",
  "VPN", "ブイピーエヌ", "プロキシ", "proxy",
  "Cookie", "クッキー", "cookie", "セッション", "session", "キャッシュ", "cache",
  "ブラウザ", "browser", "Chrome", "Firefox", "Safari", "Edge", "Opera",
  "User Agent", "ユーザーエージェント",
  
  // デバイス情報
  "デバイス", "device", "端末", "スマホ", "スマートフォン", "smartphone", "携帯", "ケータイ", "mobile",
  "PC", "パソコン", "パーソナルコンピュータ", "computer", "ノートPC", "laptop", "デスクトップ", "desktop",
  "タブレット", "tablet", "iPad", "アイパッド",
  "iPhone", "アイフォン", "Android", "アンドロイド",
  "Mac", "マック", "MacBook", "iMac", "Windows", "ウィンドウズ", "Linux", "リナックス",
  "IMEI", "シリアル番号", "serial number", "製造番号", "model", "モデル", "型番",
  "OS", "オーエス", "バージョン", "version", "ビルド", "build",
  
  // ============================================================
  // 決済・金融情報（最重要）
  // ============================================================
  // クレジットカード
  "クレジットカード", "クレカ", "カード", "カード番号", "card", "credit", "credit card", "debit", "デビット",
  "VISA", "ビザ", "Mastercard", "マスター", "JCB", "ジェーシービー", "American Express", "AMEX", "アメックス",
  "Diners", "ダイナース", "Discover", "ディスカバー",
  "有効期限", "expiry", "expire", "expiration", "exp date", "mm/yy",
  "セキュリティコード", "CVV", "CVC", "CVV2", "security code", "verification code",
  "カード名義", "名義人", "cardholder", "card holder", "name on card",
  "暗証番号", "PIN", "ピン", "pin code",
  
  // 銀行・口座
  "銀行", "銀行口座", "口座", "口座番号", "account", "bank account", "account number",
  "支店", "支店名", "支店番号", "branch", "branch code",
  "普通", "当座", "定期", "貯蓄", "saving", "savings", "checking",
  "預金", "貯金", "残高", "balance", "deposit",
  "振込", "送金", "transfer", "wire", "remittance",
  "引き落とし", "自動引き落とし", "口座振替", "direct debit",
  "キャッシュカード", "通帳", "bankbook", "passbook",
  "暗証番号", "PIN",
  
  // 主要銀行
  "三菱UFJ", "みずほ", "三井住友", "りそな", "ゆうちょ", "郵便局",
  "楽天銀行", "イオン銀行", "セブン銀行", "ソニー銀行", "住信SBI", "PayPay銀行", "ジャパンネット",
  
  // マイナンバー・身分証明書
  "マイナンバー", "個人番号", "通知カード", "mynumber", "マイナ", "マイナカード", "マイナンバーカード",
  "12桁", "12ケタ",
  
  "免許証", "運転免許", "免許", "運転免許証", "license", "driver's license", "driver license", "免許番号",
  "保険証", "健康保険", "健康保険証", "保険", "insurance", "health insurance", "保険証番号", "被保険者番号",
  "パスポート", "旅券", "passport", "旅券番号", "passport number",
  "学生証", "社員証", "身分証", "身分証明書", "ID card", "identification", "ID",
  "在留カード", "特別永住者証明書", "residence card",
  
  "年金", "年金番号", "基礎年金番号", "pension", "pension number",
  "納税者番号", "tax", "納税",
  
  // 決済サービス・電子マネー
  "PayPay", "ペイペイ", "paypay",
  "楽天ペイ", "楽天pay", "Rakuten Pay",
  "LINE Pay", "ラインペイ", "line pay",
  "メルペイ", "merpay",
  "au PAY", "auペイ", "aupay",
  "d払い", "dポイント",
  "Amazon Pay", "アマゾンペイ",
  "PayPal", "ペイパル", "paypal",
  "Stripe", "ストライプ", "stripe",
  "Square", "スクエア", "square",
  "Apple Pay", "アップルペイ", "applepay",
  "Google Pay", "グーグルペイ", "googlepay",
  "Samsung Pay", "サムスンペイ",
  "Suica", "スイカ", "suica",
  "PASMO", "パスモ", "pasmo",
  "ICOCA", "イコカ", "icoca",
  "Kitaca", "キタカ",
  "TOICA", "トイカ",
  "manaca", "マナカ",
  "SUGOCA", "スゴカ",
  "nimoca", "ニモカ",
  "はやかけん",
  "nanaco", "ナナコ", "nanaco",
  "WAON", "ワオン", "waon",
  "Edy", "エディ", "楽天Edy", "edy",
  "iD", "アイディー",
  "QUICPay", "クイックペイ", "quicpay",
  "電子マネー", "IC", "QRコード", "QR", "バーコード", "barcode",
  "コード決済", "スマホ決済", "キャッシュレス", "cashless",
  "ウォレット", "wallet", "残高", "チャージ", "charge",
  
  // 暗号資産・ブロックチェーン
  "暗号資産", "仮想通貨", "暗号通貨", "cryptocurrency", "crypto",
  "Bitcoin", "ビットコイン", "BTC", "bitcoin", "btc",
  "Ethereum", "イーサリアム", "ETH", "ethereum", "eth",
  "ウォレット", "wallet", "ウォレットアドレス", "wallet address", "アドレス",
  "秘密鍵", "private key", "プライベートキー", "シードフレーズ", "seed phrase", "ニーモニック",
  "公開鍵", "public key", "パブリックキー",
  "取引所", "exchange", "Coinbase", "Binance", "bitFlyer", "Coincheck",
  
  // 証券・投資
  "証券", "証券口座", "証券会社", "securities", "brokerage",
  "株", "株式", "stock", "equity", "銘柄",
  "投資", "投資信託", "investment", "mutual fund", "ETF",
  "口座番号", "証券コード",
  "野村", "大和", "SMBC日興", "みずほ", "SBI", "楽天証券", "マネックス",
  
  // ============================================================
  // 家族・人間関係
  // ============================================================
  "家族", "家庭", "family", "household",
  "父", "父親", "お父さん", "パパ", "親父", "father", "dad", "papa",
  "母", "母親", "お母さん", "ママ", "おかん", "mother", "mom", "mama",
  "親", "両親", "parent", "parents",
  "兄", "お兄さん", "お兄ちゃん", "兄貴", "brother", "older brother",
  "姉", "お姉さん", "お姉ちゃん", "sister", "older sister",
  "弟", "younger brother",
  "妹", "younger sister",
  "兄弟", "姉妹", "きょうだい", "sibling", "siblings",
  "祖父", "祖父母", "おじいさん", "おじいちゃん", "じいじ", "grandfather", "grandpa",
  "祖母", "おばあさん", "おばあちゃん", "ばあば", "grandmother", "grandma",
  "孫", "grandchild", "grandson", "granddaughter",
  "叔父", "伯父", "おじさん", "uncle",
  "叔母", "伯母", "おばさん", "aunt",
  "甥", "姪", "nephew", "niece",
  "いとこ", "従兄弟", "従姉妹", "cousin",
  
  "夫", "旦那", "主人", "husband", "spouse",
  "妻", "嫁", "奥さん", "家内", "wife", "spouse",
  "配偶者", "パートナー", "partner", "married",
  "婚約者", "フィアンセ", "fiancé", "fiancée", "engaged",
  "彼氏", "彼", "boyfriend", "bf",
  "彼女", "girlfriend", "gf",
  "恋人", "lover", "恋", "愛",
  "元カレ", "元カノ", "ex",
  
  "子供", "子", "息子", "娘", "長男", "次男", "長女", "次女", "child", "children", "son", "daughter", "kid",
  "赤ちゃん", "乳児", "幼児", "baby", "infant", "toddler",
  
  "友達", "友人", "友", "知人", "知り合い", "仲間", "friend", "acquaintance", "buddy", "pal",
  "親友", "best friend", "bff", "マブダチ",
  "同僚", "colleague", "coworker", "仕事仲間",
  "上司", "boss", "supervisor", "manager", "部長", "課長", "係長", "主任",
  "部下", "subordinate",
  "先輩", "後輩", "同期", "同級生", "クラスメート", "classmate",
  "先生", "教師", "teacher", "instructor", "professor", "教授",
  "生徒", "学生", "児童", "student", "pupil",
  
  // ============================================================
  // 学校・教育機関
  // ============================================================
  "学校", "学校名", "校名", "school", "educational institution",
  "小学校", "elementary school", "primary school", "小学", "しょうがく",
  "中学校", "junior high school", "middle school", "中学", "ちゅうがく",
  "高校", "高等学校", "high school", "こうこう", "高専", "工業高専",
  "大学", "大学校", "university", "college", "uni", "だいがく",
  "短大", "短期大学", "junior college",
  "専門学校", "vocational school", "専門", "せんもん",
  "大学院", "graduate school", "院", "修士", "博士", "master", "phd", "doctor",
  "予備校", "塾", "juku", "cram school", "学習塾", "進学塾",
  "幼稚園", "保育園", "kindergarten", "nursery", "preschool",
  
  "学部", "faculty", "department", "学科", "専攻", "major", "コース", "course",
  "文学部", "法学部", "経済学部", "商学部", "理学部", "工学部", "農学部", "医学部", "薬学部", "看護学部",
  "教育学部", "芸術学部", "体育学部", "情報学部",
  
  "学年", "grade", "学級", "クラス", "組", "class", "ホームルーム", "homeroom",
  "1年", "2年", "3年", "4年", "一年生", "二年生", "三年生", "四年生",
  "freshman", "sophomore", "junior", "senior",
  
  "出席番号", "学籍番号", "student number", "student id", "学生証番号",
  "成績", "grade", "score", "点数", "評価", "通知表", "成績表", "report card",
  "GPA", "偏差値", "順位", "rank", "ranking",
  "テスト", "試験", "考査", "exam", "examination", "test", "quiz", "中間", "期末", "模試",
  "入試", "受験", "entrance exam", "受験番号",
  
  "卒業", "graduation", "卒業年", "卒業証書", "diploma", "学位", "degree",
  "入学", "admission", "入学年", "入学式",
  "転校", "転入", "編入", "transfer",
  "退学", "中退", "dropout",
  
  "授業", "lecture", "class", "lesson", "時間割", "timetable", "schedule", "syllabus",
  "部活", "部活動", "クラブ", "club", "サークル", "circle", "同好会",
  "運動部", "文化部", "帰宅部",
  
  // 主要大学（一部）
  "東大", "東京大学", "University of Tokyo", "todai",
  "京大", "京都大学", "Kyoto University", "kyodai",
  "阪大", "大阪大学", "Osaka University",
  "東工大", "東京工業大学", "Tokyo Tech",
  "一橋", "一橋大学", "Hitotsubashi",
  "東北大", "名古屋大", "九州大", "北海道大",
  "早稲田", "早大", "Waseda",
  "慶應", "慶應義塾", "慶大", "Keio",
  "上智", "Sophia",
  "明治", "青山", "立教", "中央", "法政", "MARCH",
  "関西", "関学", "同志社", "立命館", "関関同立",
  
  // ============================================================
  // 職場・会社情報
  // ============================================================
  "会社", "会社名", "企業", "企業名", "勤務先", "職場", "勤め先", "勤め", "就職先",
  "company", "corporation", "employer", "workplace", "office",
  "株式会社", "有限会社", "合同会社", "Co., Ltd.", "Inc.", "Corp.", "LLC",
  
  "部署", "部門", "部", "課", "係", "室", "グループ", "チーム",
  "department", "division", "section", "group", "team", "unit",
  
  "役職", "肩書き", "職位", "position", "title", "rank",
  "社長", "会長", "CEO", "代表", "代表取締役", "president", "chairman",
  "副社長", "専務", "常務", "取締役", "役員", "executive", "director",
  "部長", "次長", "課長", "係長", "主任", "manager", "chief", "supervisor",
  "一般社員", "平社員", "staff", "employee",
  "派遣", "派遣社員", "contract", "contractor",
  "アルバイト", "バイト", "パート", "part-time", "part time job",
  "インターン", "intern", "internship",
  "フリーランス", "freelance", "個人事業主",
  
  "社員番号", "従業員番号", "社員証番号", "employee number", "employee id", "staff number",
  "名刺", "business card", "名刺番号",
  
  "給与", "給料", "月給", "年収", "収入", "報酬", "賃金", "手取り",
  "salary", "wage", "income", "pay", "compensation", "earnings",
  "ボーナス", "賞与", "bonus", "incentive",
  "残業", "残業代", "overtime", "時給", "hourly wage",
  
  "雇用", "採用", "内定", "employment", "hiring", "job offer",
  "退職", "退社", "辞職", "resignation", "retirement", "quit",
  "解雇", "クビ", "リストラ", "fired", "layoff", "termination",
  
  "出勤", "出社", "勤怠", "attendance", "出退勤", "タイムカード",
  "休暇", "有給", "休日", "holiday", "vacation", "leave", "欠勤", "遅刻", "早退",
  
  "契約", "雇用契約", "contract", "employment contract",
  "守秘義務", "NDA", "機密保持", "confidentiality", "non-disclosure",
  
  // ============================================================
  // 医療・健康情報
  // ============================================================
  "病院", "医院", "クリニック", "診療所", "hospital", "clinic", "医療機関",
  "かかりつけ", "主治医", "担当医", "doctor", "physician",
  
  "病気", "疾患", "病名", "診断", "症状", "disease", "illness", "condition", "diagnosis", "symptom",
  "がん", "癌", "cancer", "腫瘍", "tumor",
  "糖尿病", "diabetes", "高血圧", "hypertension",
  "うつ", "うつ病", "depression", "不安", "anxiety", "パニック", "panic",
  "統合失調症", "schizophrenia", "双極性", "bipolar",
  "ADHD", "ADD", "自閉症", "autism", "発達障害",
  "認知症", "アルツハイマー", "dementia", "Alzheimer",
  "アレルギー", "allergy", "喘息", "asthma", "花粉症",
  "感染症", "ウイルス", "virus", "細菌", "bacteria", "インフル", "コロナ", "COVID",
  "怪我", "ケガ", "injury", "骨折", "fracture", "捻挫", "sprain",
  
  "薬", "医薬品", "medicine", "medication", "drug", "処方薬", "prescription",
  "処方", "処方箋", "prescription", "服用", "飲み", "take", "dosage", "用量",
  "副作用", "side effect", "アレルギー反応",
  "ワクチン", "予防接種", "vaccine", "vaccination", "接種",
  
  "治療", "手術", "入院", "通院", "検査", "診察",
  "treatment", "surgery", "operation", "hospitalization", "examination", "checkup",
  "カルテ", "診断書", "medical record", "medical certificate",
  
  "血液型", "blood type", "A型", "B型", "O型", "AB型", "Rh", "RhD",
  "身長", "体重", "BMI", "height", "weight", "体格", "身体", "体型",
  "血圧", "血糖値", "コレステロール", "中性脂肪",
  
  "障害", "障がい", "disability", "handicap", "身体障害", "知的障害", "精神障害",
  "車椅子", "wheelchair", "補助", "assistance",
  
  "妊娠", "出産", "pregnancy", "pregnant", "childbirth", "産婦人科",
  "生理", "月経", "menstruation", "period",
  
  "健康診断", "健診", "人間ドック", "health checkup", "physical examination",
  
  // ============================================================
  // 写真・画像・動画・メディア
  // ============================================================
  "顔", "顔写真", "face", "facial", "顔画像",
  "写真", "画像", "photo", "photograph", "picture", "image", "pic", "img",
  "動画", "ビデオ", "映像", "video", "footage", "clip", "ムービー", "movie",
  "音声", "音声ファイル", "audio", "voice", "sound",
  "録音", "recording", "record",
  "録画", "video recording", "撮影", "filming",
  
  "自撮り", "セルフィー", "selfie", "自分撮り",
  "プロフィール画像", "プロフ画", "アイコン", "icon", "avatar", "アバター",
  "カバー画像", "ヘッダー", "header", "cover", "banner",
  
  "スクリーンショット", "スクショ", "screenshot", "screen capture", "SS",
  "キャプチャ", "capture", "画面", "screen",
  
  "アルバム", "album", "ギャラリー", "gallery", "フォト", "写真集",
  "スライドショー", "slideshow",
  
  "ライブ配信", "配信", "生配信", "streaming", "live stream", "broadcast", "生放送",
  "アーカイブ", "archive", "過去配信",
  
  "編集", "加工", "フィルター", "edit", "filter", "retouch", "修正",
  "モザイク", "ぼかし", "blur", "censored", "隠す",
  
  // ============================================================
  // 生体情報・身体特徴
  // ============================================================
  "指紋", "fingerprint", "拇印", "thumb print",
  "顔認証", "face recognition", "Face ID", "facial recognition",
  "虹彩", "虹彩認証", "iris", "iris scan",
  "網膜", "retina", "retina scan",
  "静脈", "静脈認証", "vein", "vein authentication",
  "生体認証", "生体情報", "biometric", "biometric authentication", "バイオメトリクス",
  "声紋", "voiceprint", "voice recognition", "音声認証",
  "DNA", "遺伝子", "genetic", "genome",
  
  "容姿", "外見", "見た目", "appearance", "looks",
  "特徴", "feature", "ほくろ", "mole", "あざ", "birthmark", "傷跡", "scar", "タトゥー", "tattoo", "刺青",
  
  // ============================================================
  // 秘密・機密・プライバシー
  // ============================================================
  "秘密", "ひみつ", "secret", "秘",
  "内緒", "ないしょ", "confidential",
  "隠", "隠す", "かくす", "hide", "hidden", "隠蔽",
  "伏せる", "非表示", "invisible",
  
  "個人情報", "personal information", "personal data", "PII",
  "機密", "機密情報", "機密事項", "classified", "classified information",
  "プライバシー", "privacy", "プライベート", "private",
  "センシティブ", "sensitive", "要配慮個人情報",
  
  "公開", "公表", "公", "public", "open",
  "非公開", "非公表", "closed", "private", "非表示",
  "限定公開", "限定", "limited", "restricted",
  "鍵垢", "鍵アカウント", "private account", "protected",
  
  "匿名", "anonymous", "匿名性", "anonymity", "名無し", "名無しさん",
  "本名", "real name", "実名",
  
  // ============================================================
  // 契約・法的文書
  // ============================================================
  "契約", "契約書", "contract", "agreement",
  "同意", "同意書", "consent", "agreement",
  "署名", "サイン", "sign", "signature", "自署",
  "印鑑", "判子", "ハンコ", "印", "stamp", "seal", "実印", "認印", "シャチハタ",
  "捺印", "押印",
  
  "規約", "利用規約", "terms", "terms of service", "TOS", "terms and conditions",
  "プライバシーポリシー", "privacy policy", "個人情報保護方針",
  "免責", "disclaimer", "免責事項",
  
  "遺言", "遺言書", "will", "testament",
  "戸籍", "koseki", "family register", "戸籍謄本",
  "住民票", "住民票の写し", "certificate of residence",
  
  // ============================================================
  // センシティブ属性
  // ============================================================
  "性別", "gender", "男", "女", "male", "female", "性",
  "性的指向", "sexual orientation", "LGBT", "LGBTQ", "LGBTQIA", "同性愛", "異性愛",
  "トランスジェンダー", "transgender", "性同一性", "gender identity",
  
  "国籍", "nationality", "citizenship", "市民権",
  "人種", "民族", "race", "ethnicity", "ethnic",
  "出身", "出身地", "出身国", "origin", "birthplace",
  "移民", "immigrant", "外国人", "foreigner", "在留", "ビザ", "visa",
  
  "宗教", "信仰", "religion", "religious", "faith", "belief",
  "仏教", "Buddhism", "神道", "Shinto", "キリスト教", "Christian", "イスラム", "Islam", "ヒンドゥー", "Hindu",
  
  "政治", "政党", "political", "politics", "party", "思想", "ideology",
  "右翼", "左翼", "保守", "革新", "リベラル", "liberal", "conservative",
  "支持", "投票", "vote", "選挙", "election",
  
  "労働組合", "組合", "union", "labor union",
  
  "犯罪", "犯罪歴", "前科", "逮捕", "起訴", "有罪", "無罪",
  "criminal", "criminal record", "arrest", "conviction", "guilty", "innocent",
  
  // ============================================================
  // 特定につながる詳細情報
  // ============================================================
  // 車・交通
  "車", "自動車", "車種", "car", "vehicle", "automobile",
  "ナンバープレート", "車のナンバー", "ナンバー", "license plate", "plate number", "車両番号",
  "登録番号", "車検", "車検証",
  "バイク", "オートバイ", "motorcycle", "bike",
  
  // ペット
  "ペット", "pet", "犬", "dog", "猫", "cat", "動物", "animal",
  "ペットの名前", "pet name", "飼い", "飼っている",
  
  // 趣味・嗜好
  "趣味", "hobby", "hobbies", "特技", "特技", "skill", "好き", "like", "favorite", "お気に入り",
  "嫌い", "苦手", "dislike", "hate",
  "習い事", "lesson", "習っている", "learning",
  
  // 予定・行動パターン
  "予定", "スケジュール", "カレンダー", "schedule", "calendar", "plan", "予約", "reservation", "booking",
  "いつ", "何時", "when", "what time", "時間", "time",
  "どこ", "where", "場所", "place", "location",
  "出かける", "外出", "出る", "going out", "leave",
  "帰宅", "帰る", "return", "come home", "back",
  "留守", "不在", "家にいない", "away", "not home", "absent",
  "旅行", "旅", "travel", "trip", "vacation", "観光", "tour",
  "出張", "business trip",
  
  // 日常の行動
  "起床", "wake up", "起きる", "目覚め",
  "就寝", "寝る", "sleep", "bedtime",
  "通勤", "通学", "commute", "通っている",
  "ルーティン", "routine", "日課", "習慣", "habit",
  
  // 購買・消費行動
  "買う", "購入", "buy", "purchase", "注文", "order", "shopping", "買い物",
  "クレジットカード情報", "決済情報", "payment information",
  "購入履歴", "注文履歴", "purchase history", "order history",
  "欲しい", "want", "wish", "ほしい",
  
  // ============================================================
  // デジタルフットプリント
  // ============================================================
  "検索履歴", "search history", "閲覧履歴", "browsing history", "履歴", "history",
  "ブックマーク", "bookmark", "お気に入り", "favorites",
  "ダウンロード", "download", "ダウンロード履歴",
  
  "位置情報履歴", "location history", "行動履歴", "activity log",
  "タイムライン", "timeline", "足跡", "footprint",
  
  "連絡先", "アドレス帳", "contacts", "contact list", "電話帳",
  "通話履歴", "call history", "call log", "着信", "発信",
  
  // ============================================================
  // 認証・セキュリティ（追加）
  // ============================================================
  "秘密の質問", "security question", "母親の旧姓", "maiden name", "初めてのペット", "first pet",
  "出身小学校", "elementary school name",
  
  "暗号化", "encryption", "復号", "decryption", "decrypt",
  "ハッシュ", "hash", "ソルト", "salt",
  
  // ============================================================
  // ファイル・データ
  // ============================================================
  "ファイル", "file", "document", "ドキュメント", "書類",
  "PDF", "Word", "Excel", "PowerPoint", "txt", "csv",
  "zip", "圧縮", "compress", "解凍", "extract",
  
  "バックアップ", "backup", "復元", "restore", "リストア",
  "同期", "sync", "synchronize", "クラウド", "cloud",
  "ストレージ", "storage", "容量", "capacity",
  
  "削除", "delete", "消去", "erase", "remove", "ゴミ箱", "trash", "完全削除",
  
  // ============================================================
  // 会話・コミュニケーション内容
  // ============================================================
  "チャット", "chat", "会話", "conversation", "トーク", "talk",
  "メッセージ", "message", "msg", "やりとり",
  "通話", "電話", "call", "ビデオ通話", "video call", "音声通話", "voice call",
  
  "送信", "send", "受信", "receive", "転送", "forward",
  "既読", "read", "未読", "unread",
  
  // ============================================================
  // 方言・地域特定可能な言葉（サンプル）
  // ============================================================
  "〜やん", "〜やねん", "〜やで", "〜やけど", "〜や", // 関西弁
  "〜だべ", "〜べ", "〜だっぺ", // 東北・関東
  "〜ばい", "〜たい", "〜と", "〜っちゃ", // 九州
  "〜だら", "〜ら", "〜ずら", // 中部
  "〜じゃけん", "〜じゃけぇ", // 中国地方
  "〜やき", "〜ぜよ", // 四国
  "なまら", "したっけ", "〜っしょ", // 北海道
  "〜さー", "〜やさー", // 沖縄
  
  // ============================================================
  // 企業名パターン
  // ============================================================
  "株式会社", "かぶしきがいしゃ", "Co., Ltd.", "Co.Ltd.", "Ltd.", "Corporation", "Corp.", "Inc.",
  "有限会社", "LLC", "合同会社", "GK",
  "社団法人", "財団法人", "NPO", "NGO",
  
  // ============================================================
  // 暗号資産・ブロックチェーン（追加）
  // ============================================================
  "NFT", "DeFi", "Web3", "DAO",
  "Ripple", "XRP", "Litecoin", "LTC", "Cardano", "ADA", "Polkadot", "DOT",
  "トークン", "token", "コイン", "coin",
  "マイニング", "mining", "ステーキング", "staking",
  "メタマスク", "MetaMask", "ハードウェアウォレット", "hardware wallet",
  "Ledger", "Trezor",
  
  // ============================================================
  // ゲーム関連（追加）
  // ============================================================
  "ゲームID", "game id", "ゲーマータグ", "gamer tag",
  "フレンドコード", "friend code", "フレンド", "friend", "フレンド登録",
  "ギルド", "guild", "クラン", "clan", "チーム名", "team name",
  "ランク", "rank", "レート", "rating", "レベル", "level",
  "セーブデータ", "save data", "セーブ", "save",
  
  "マイクラ", "Minecraft", "フォートナイト", "Fortnite", "Apex", "エーペックス",
  "LoL", "League of Legends", "Valorant", "ヴァロラント",
  "ポケモン", "Pokemon", "あつ森", "どうぶつの森", "Animal Crossing",
  "原神", "Genshin", "ウマ娘", "モンスト", "パズドラ", "FGO",
  
  // ============================================================
  // 音楽・エンタメ
  // ============================================================
  "Spotify", "スポティファイ", "Apple Music", "YouTube Music",
  "プレイリスト", "playlist", "お気に入りの曲", "favorite song",
  "サブスク", "subscription", "サブスクリプション",
  
  "Netflix", "ネットフリックス", "Amazon Prime", "Hulu", "ディズニープラス", "Disney+",
  "視聴履歴", "watch history", "お気に入り", "watchlist",
  
  // ============================================================
  // その他デジタルサービス
  // ============================================================
  "Google", "グーグル", "Gmail", "Google Drive", "グーグルドライブ",
  "Dropbox", "ドロップボックス", "OneDrive", "ワンドライブ", "iCloud", "アイクラウド",
  "Evernote", "エバーノート", "Notion", "ノーション",
  
  "Amazon", "アマゾン", "楽天", "Rakuten", "Yahoo", "ヤフー",
  "メルカリ", "mercari", "ヤフオク", "Yahoo Auction",
  "Uber", "ウーバー", "Uber Eats", "出前館",
  
  // ============================================================
  // 日時表現（個人特定に使われうる）
  // ============================================================
  "今日", "yesterday", "tomorrow", "今週", "先週", "来週", "this week", "last week", "next week",
  "今月", "先月", "来月", "this month", "last month", "next month",
  "今年", "去年", "来年", "this year", "last year", "next year",
  
  "月曜", "火曜", "水曜", "木曜", "金曜", "土曜", "日曜",
  "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday",
  "平日", "週末", "weekend", "祝日", "holiday",
  
  "朝", "昼", "夜", "morning", "afternoon", "evening", "night",
  "午前", "午後", "AM", "PM", "深夜", "midnight",
  
  // ============================================================
  // 追加の機微情報
  // ============================================================
  "HIV", "AIDS", "性病", "STD", "STI", "性感染症",
  "中絶", "abortion", "流産", "miscarriage",
  "DV", "ドメスティックバイオレンス", "domestic violence", "虐待", "abuse",
  "借金", "債務", "debt", "破産", "bankruptcy", "自己破産",
  "依存", "依存症", "addiction", "アルコール依存", "薬物依存", "ギャンブル依存",
  
  "カウンセリング", "counseling", "セラピー", "therapy", "精神科", "psychiatry", "心療内科",
  
  // ============================================================
  // 追加のオンラインサービス
  // ============================================================
  "Tinder", "ティンダー", "Match", "マッチ", "Pairs", "ペアーズ", "Omiai", "タップル", "出会い系", "マッチングアプリ",
  
  // ============================================================
  // 学校名の一般パターン
  // ============================================================
  "第一", "第二", "第三", "第〇", "〇〇小", "〇〇中", "〇〇高", "〇〇大",
  "north", "south", "east", "west", "北", "南", "東", "西", "central", "中央",
  
  // ============================================================
  // 追加の金融・決済
  // ============================================================
  "SWIFT", "スウィフト", "IBAN", "routing number", "ルーティングナンバー",
  "仮想口座", "virtual account",
  
  // ============================================================
  // その他
  // ============================================================
  "タグ", "tag", "ハッシュタグ", "hashtag", "#",
  "リンク", "link", "URL", "ユーアールエル", "http", "https",
  
  "QRコード", "QR code", "バーコード", "barcode", "二次元コード",
  
  "スキャン", "scan", "読み取り", "read",
  "コピー", "copy", "ペースト", "paste", "複製", "duplicate",
  
  "ログ", "log", "記録", "record", "履歴", "history", "アクティビティ", "activity",
  
  "設定", "settings", "config", "configuration", "環境設定", "preferences",
  "プライバシー設定", "privacy settings", "セキュリティ設定", "security settings",
  
  "本人確認", "身元確認", "identity verification", "KYC", "eKYC",
  "認証コード", "verification code", "確認コード", "confirmation code",
  
  "招待", "invite", "invitation", "招待コード", "invite code", "紹介", "referral",
  
  "サブスク", "subscription", "会員", "member", "membership", "premium", "プレミアム",
  
  "アンケート", "survey", "questionnaire", "調査", "フォーム", "form",
  
  "レビュー", "review", "評価", "rating", "口コミ", "評判", "reputation",
];

export async function RSAtool() {
    const header = createHeader("RSA暗号", "", true);
  document.body.insertBefore(header, document.body.firstChild);
  // --- 1. 演出用レイヤーの設定 ---
  const bgDiv = document.createElement("div");
  const bgAudio = document.createElement("audio");
  document.body.appendChild(bgAudio);
  Object.assign(bgDiv.style, {
    display: "none",
    position: "fixed",
    top: 0,
    left: 0,
    width: "100vw",
    height: "100vh",
    backgroundSize: "cover",
    backgroundPosition: "center",
    zIndex: 9999,
    opacity: 0,
    transition: "opacity 0.5s",
    pointerEvents: "none",
  });
  document.body.appendChild(bgDiv);

  const mainContainer = document.createElement("div");
  Object.assign(mainContainer.style, {
    maxWidth: "800px",
    margin: "0 auto",
    padding: "20px",
    fontFamily: "sans-serif",
  });
  document.body.appendChild(mainContainer);

  function createSection(name) {
    const sec = document.createElement("div");
    Object.assign(sec.style, {
      border: "1px solid #ddd",
      borderRadius: "8px",
      padding: "15px",
      marginBottom: "20px",
      background: "#fff",
    });
    const h3 = document.createElement("h3");
    h3.textContent = name;
    h3.style.marginTop = "0";
    sec.appendChild(h3);
    mainContainer.appendChild(sec);
    return sec;
  }

  // --- 2. 鍵管理セクション ---
  const keySec = createSection("鍵管理 (RSA)");
  const genBtn = document.createElement("button");
  genBtn.textContent = "✨ 新しい鍵ペアを生成してセット";
  genBtn.style.marginBottom = "10px";
  keySec.appendChild(genBtn);

  const pemInput = document.createElement("textarea");
  pemInput.placeholder = "秘密鍵 (PEM形式)";
  Object.assign(pemInput.style, { width: "100%", height: "150px" });
  keySec.appendChild(pemInput);

  const pubInput = document.createElement("textarea");
  pubInput.placeholder = "公開鍵 (PEM形式)";
  Object.assign(pubInput.style, {
    width: "100%",
    height: "150px",
    marginTop: "10px",
  });
  keySec.appendChild(pubInput);

  // --- 3. 初期化とパラメータ取得 ---
  const urlParams = new URLSearchParams(window.location.search);
  const isinmumode = urlParams.get("type") === "inmu";
  const currentUrl = new URL(window.location.href);
  const cryptos = new RSA();
  isinmu(isinmumode);

  try {
    await cryptos.initAsync(
      "https://cdn.jsdelivr.net/gh/Kazuhiro-Tokumoto/rsa@main/primes.bin",
    );
  } catch (e) {
    console.error("初期化エラー:", e);
  }

  let parsedKeysa, parsedPubKeys;

  // --- 4. 演出ロジック (isinmumode時のみ有効) ---
  function playSpecialAudio(text) {
    if (!isinmumode) return;
    const isDetected =
      inmuData[0].high.some((word) => text.includes(word)) ||
      inmuData[0].mid.some((word) => text.includes(word));
    if (isDetected) {
      const audio = new Audio(
        "https://sugtao4423.xyz/inm/四章/野獣/野獣「イキスギイクゥ！イクゥイクイクイク…　アッ…　ンアッー！」.wav",
      );
      audio.play().catch(() => {});
    }
  }

  function processMemeEffect(text, force = false) {
    if (!isinmumode) return;
    const isPrivacy = privacyWords.some((word) => text.includes(word));

    if (isPrivacy && isinmumode) {
      bgAudio.src = "https://www.myinstants.com/media/sounds/kai-shi-dana.mp3";
    } else {
      return;
    }

    bgAudio.play().catch(() => {});
    bgAudio.onended = () => {};
  }
  pubInput.oninput = () => {
    try {
      const pubPem = pubInput.value.trim();
      if (pubPem.includes("BEGIN PUBLIC KEY")) {
        // 公開鍵をパースして変数に格納
        parsedPubKeys = cryptos.parsePublicKeyPem(pubPem);

        // 公開鍵だけでは秘密鍵(n, e, d, p, q)は復元できないので null に
        parsedKeysa = null;

        // 秘密鍵入力欄は紛らわしいので空にするか、そのままにする
        // pemInput.value = "";
      }
    } catch (e) {
      parsedPubKeys = null;
      console.error("公開鍵のパースに失敗しました", e);
    }
  };

  const updateKeys = () => {
    try {
      parsedKeysa = cryptos.parsePrivateKeyPem(pemInput.value);
      const pubPem = cryptos.PublicKeyPem(parsedKeysa.n, parsedKeysa.e);
      pubInput.value = pubPem;
      parsedPubKeys = cryptos.parsePublicKeyPem(pubPem);
    } catch (e) {
      parsedKeysa = parsedPubKeys = null;
    }
  };

  pemInput.oninput = () => {
    updateKeys();
    processMemeEffect(pemInput.value);
  };

  genBtn.onclick = async () => {
    genBtn.textContent = "鍵ペアを生成中...";
    await new Promise((r) => setTimeout(r, 100));
    console.time("keygen");
    const keys = await cryptos.generateRSAKeyPair(4096);
    /*
    if (isinmumode) {
      const audio = new Audio(
        "https://kazuhiro-tokumoto.github.io/rsa/img/yarimasune.mp3",
      );
      const pic = "url('https://kazuhiro-tokumoto.github.io/rsa/img/yaju.jpg')";
      bgDiv.style.backgroundImage = pic;
      bgDiv.style.display = "block";
      setTimeout(() => {
        bgDiv.style.opacity = "1";
      }, 10);
      audio.play().catch(() => {});
      audio.onended = () => {
        bgDiv.style.opacity = "0";
        setTimeout(() => {
          bgDiv.style.display = "none";
        }, 500);
      };
    }
    pemInput.value = cryptos.exportToPem(
      keys.n,
      keys.e,
      keys.d,
      keys.p,
      keys.q,
    );
    */
    updateKeys();
    genBtn.textContent = "✨ 新しい鍵ペアを生成してセット";
    console.timeEnd("keygen");
    //processMemeEffect("", true);
    alert("鍵が完成しました");
  };

  // --- 5. 操作セクションのレイアウト ---
  const opSec = createSection("操作 (署名・検証・暗号・復号)");
  const inputmsg = document.createElement("textarea");
  inputmsg.placeholder = "処理するメッセージを入力してください";
  Object.assign(inputmsg.style, { width: "100%", height: "60px" });
  opSec.appendChild(inputmsg);

  const btnGrid = document.createElement("div");
  Object.assign(btnGrid.style, {
    display: "grid",
    gridTemplateColumns: "1fr 1fr",
    gap: "10px",
    marginTop: "10px",
  });
  opSec.appendChild(btnGrid);

  const btns = {
    sign: document.createElement("button"),
    verify: document.createElement("button"),
    enc: document.createElement("button"),
    dec: document.createElement("button"),
    copy: document.createElement("button"),
    clear: document.createElement("button"),
  };
  btns.sign.textContent = "署名する";
  btns.verify.textContent = "検証する";
  btns.enc.textContent = "暗号化する";
  btns.dec.textContent = "復号化する";
  btns.copy.textContent = "結果をコピー";
  btns.copy.style.color = "blue";
  btns.clear.textContent = "入力を削除";
  btns.clear.style.color = "red";

  // コピーと削除を横いっぱいに広げる
  btns.copy.style.gridColumn = "span 2";
  btns.clear.style.gridColumn = "span 2";

  [btns.sign, btns.verify, btns.enc, btns.dec, btns.copy, btns.clear].forEach(
    (b) => btnGrid.appendChild(b),
  );

  const resultArea = document.createElement("pre");
  Object.assign(resultArea.style, {
    background: "#f4f4f4",
    padding: "15px",
    marginTop: "20px",
    whiteSpace: "pre-wrap",
    wordBreak: "break-all",
    minHeight: "100px",
    border: "1px solid #ccc",
  });
  opSec.appendChild(resultArea);

  // --- 6. 各ボタンのアクション ---
  btns.sign.onclick = async () => {
    if (!parsedKeysa) return alert("秘密鍵が設定されていません。");
    console.time("sign");
    const sig = await cryptos.signStringToBase64(
      inputmsg.value,
      parsedKeysa.d,
      parsedKeysa.p,
      parsedKeysa.q,
      parsedKeysa.n,
    );
    console.timeEnd("sign");
    resultArea.textContent = `【署名結果】\n${sig}`;
    //playSpecialAudio(inputmsg.value);
  };

  btns.verify.onclick = async () => {
    const sig = prompt("検証する署名を入力してください:");
    if (!sig) return;
    if (!parsedPubKeys) return alert("公開鍵が設定されていません。");
    console.time("verify");
    const ok = await cryptos.verifyBase64Signature(
      inputmsg.value,
      sig,
      parsedPubKeys.e,
      parsedPubKeys.n,
    );
    console.timeEnd("verify");
    resultArea.textContent = ok
      ? "✅ 検証に成功しました。正当な署名です。"
      : "❌ 検証に失敗しました。不正な署名です。";
    //playSpecialAudio(inputmsg.value);
    //processMemeEffect(inputmsg.value);
  };

  btns.enc.onclick = async () => {
    if (!parsedPubKeys) return alert("公開鍵が設定されていません。");
    console.time("encrypt");
    const enc = await cryptos.encryptStringToBase64(
      inputmsg.value,
      parsedPubKeys.e,
      parsedPubKeys.n,
    );
    console.timeEnd("encrypt");
    resultArea.textContent = `【暗号化データ】\n${enc}`;
    //playSpecialAudio(inputmsg.value);
    //processMemeEffect(inputmsg.value);
  };

  btns.dec.onclick = async () => {
    if (!parsedKeysa) return alert("秘密鍵が設定されていません。");
    console.time("decrypt");
    const dec = await cryptos.decryptBase64ToString(
      inputmsg.value,
      parsedKeysa.d,
      parsedKeysa.p,
      parsedKeysa.q,
      parsedKeysa.n,
    );
    console.timeEnd("decrypt");
    resultArea.textContent = `【復号結果】\n${dec}`;
    //playSpecialAudio(dec);
    //processMemeEffect(dec);
  };

  btns.copy.onclick = async () => {
    const text = resultArea.textContent.split("\n").slice(1).join("\n");
    if (text) {
      await navigator.clipboard.writeText(text);
      alert("クリップボードにコピーしました。");
      if (isinmumode)// processMemeEffect("copy", true);
      //playSpecialAudio(text);
    }
  };

  btns.clear.onclick = () => {
    inputmsg.value = "";
    resultArea.textContent = "";
  };

  // --- 7. URL・モード管理 ---
  const privkeyParam = urlParams.get("privkey");
  if (privkeyParam) {
    try {
      pemInput.value = atob(privkeyParam);
      updateKeys();
      currentUrl.searchParams.delete("privkey");
      window.history.replaceState({}, "", currentUrl.toString());
    } catch (e) {
      console.error(e);
    }
  }

  const modeBtn = document.createElement("button");
  modeBtn.textContent = isinmumode ? "通常モードへ" : "特別モードへ";
  Object.assign(modeBtn.style, {
    position: "fixed",
    bottom: "20px",
    right: "20px",
  });
  modeBtn.onclick = () => {
    const url = new URL(window.location.href);
    if (parsedKeysa) url.searchParams.set("privkey", btoa(pemInput.value));
    isinmumode
      ? url.searchParams.delete("type")
      : url.searchParams.set("type", "inmu");
    window.location.href = url.toString();
  };

  if (urlParams.get("mode") === "switch") {
    document.body.appendChild(modeBtn);
  } else if (urlParams.get("mode") === "") {
    currentUrl.searchParams.set("mode", "switch");
    window.location.href = currentUrl.toString();
  } else if (urlParams.get("mode") !== null) {
    currentUrl.searchParams.set("roop", "true");
    window.location.href = currentUrl.toString();
  }

  if (urlParams.get("roop") === "true") {
    alert("不正な操作が検出されました。");
    for (let i = 0; i < 1000; i++) {
      console.log("System loop...");
    }
    currentUrl.searchParams.delete("roop");
    currentUrl.searchParams.set("mode", "switch");
    window.location.href = currentUrl.toString();
  }
  async function megaTest() {
  const rsa = new RSA();
  
  console.log("=== 超大量データテスト ===\n");
  
  const { e, d, p, q, n } = await rsa.generateRSAKeyPair(4096);
  
  // 1KB
  console.log("--- 1KB ---");
  const text1kb = "あ".repeat(333);
  console.time("暗号化 1KB");
  const enc1 = await rsa.encryptStringToBase64(text1kb, e, n);
  console.timeEnd("暗号化 1KB");
  console.time("復号 1KB");
  const dec1 = await rsa.decryptBase64ToString(enc1, d, p, q, n);
  console.timeEnd("復号 1KB");
  console.log("一致:", text1kb === dec1);
  
  // 10KB
  console.log("\n--- 10KB ---");
  const text10kb = "あ".repeat(3333);
  console.time("暗号化 10KB");
  const enc2 = await rsa.encryptStringToBase64(text10kb, e, n);
  console.timeEnd("暗号化 10KB");
  console.time("復号 10KB");
  const dec2 = await rsa.decryptBase64ToString(enc2, d, p, q, n);
  console.timeEnd("復号 10KB");
  console.log("一致:", text10kb === dec2);
  
  // 100KB
  console.log("\n--- 100KB ---");
  const text100kb = "あ".repeat(33333);
  console.time("暗号化 100KB");
  const enc3 = await rsa.encryptStringToBase64(text100kb, e, n);
  console.timeEnd("暗号化 100KB");
  console.time("復号 100KB");
  const dec3 = await rsa.decryptBase64ToString(enc3, d, p, q, n);
  console.timeEnd("復号 100KB");
  console.log("一致:", text100kb === dec3);
  
  // 500KB
  console.log("\n--- 500KB ---");
  const text500kb = "あ".repeat(166666);
  console.time("暗号化 500KB");
  const enc4 = await rsa.encryptStringToBase64(text500kb, e, n);
  console.timeEnd("暗号化 500KB");
  console.time("復号 500KB");
  const dec4 = await rsa.decryptBase64ToString(enc4, d, p, q, n);
  console.timeEnd("復号 500KB");
  console.log("一致:", text500kb === dec4);
  
  // 1MB
  console.log("\n--- 1MB ---");
  const text1mb = "あ".repeat(333333);
  console.time("暗号化 1MB");
  const enc5 = await rsa.encryptStringToBase64(text1mb, e, n);
  console.timeEnd("暗号化 1MB");
  console.time("復号 1MB");
  const dec5 = await rsa.decryptBase64ToString(enc5, d, p, q, n);
  console.timeEnd("復号 1MB");
  console.log("一致:", text1mb === dec5);
}

//megaTest();
}

const delay = Math.random() * 1000;
await new Promise((r) => setTimeout(r, delay));
main();
//npx prettier --write src/rsa.ts
//npx tsc
//npx tsx
