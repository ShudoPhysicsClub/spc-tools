// ===== グローバル変数 =====
let smallPrimesBI = [];
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
function rnd(n) {
    const bl = bitLength(n);
    const byteLen = (bl + 7) >> 3;
    const uint8 = new Uint8Array(byteLen);
    const mask = (1n << BigInt(bl)) - 1n;
    while (true) {
        globalThis.crypto.getRandomValues(uint8);
        const num = bytesToBigInt(uint8) & mask;
        if (num > 0n && num < n)
            return num;
    }
}
// ===== マイン流 最強モンゴメリ modExp (フル実装) =====
function modExp(base, exp, mod) {
    // 指数のビット長に応じてk（ウィンドウサイズ）を決定
    let k = 5;
    const bits = bitLength(mod);
    if (bits > 2048)
        k = 7;
    else if (bits > 1024)
        k = 6;
    const modBits = BigInt(bits);
    const R = 1n << modBits;
    const mask = R - 1n;
    // モンゴメリ定数 nPrime の計算 (拡張ユークリッド法)
    let t = 0n, newT = 1n, r = R, m = mod;
    while (m !== 0n) {
        const q = r / m;
        [t, newT] = [newT, t - q * newT];
        [r, m] = [m, r - q * m];
    }
    const nPrime = (R - (t < 0n ? t + R : t)) & mask;
    // モンゴメリ・リダクション関数
    const reduce = (T) => {
        const u = ((T & mask) * nPrime) & mask;
        const x = (T + u * mod) >> modBits;
        return x >= mod ? x - mod : x;
    };
    // プリコンピュート・テーブル作成 (スライディングウィンドウ)
    const tableSize = 1 << (k - 1);
    const table = new Array(tableSize);
    const baseBar = (base << modBits) % mod;
    const baseBar2 = reduce(baseBar * baseBar);
    table[0] = baseBar;
    for (let i = 1; i < tableSize; i++) {
        table[i] = reduce(table[i - 1] * baseBar2);
    }
    // スライディングウィンドウによるべき乗計算
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
// ===== 爆速 Miller-Rabin (modExpを最小限に) =====
function isProbablyPrime(n, k = 15) {
    if (n <= 3n)
        return n > 1n;
    if (!(n & 1n))
        return false;
    // 試し割り (既にBigInt化されたグローバル配列を使用)
    for (let j = 0; j < smallPrimesBI.length; j++) {
        if (n % smallPrimesBI[j] === 0n)
            return n === smallPrimesBI[j];
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
        const a = i < bases.length ? bases[i] : rnd(nm1);
        // 最初だけ重い modExp
        let x = modExp(a, d, n);
        if (x === 1n || x === nm1)
            continue;
        let composite = true;
        for (let r = 1; r < s; r++) {
            // 2乗計算は modExp を通さず直接演算
            x = (x * x) % n;
            if (x === nm1) {
                composite = false;
                break;
            }
            if (x === 1n)
                return false;
        }
        if (composite)
            return false;
    }
    return true;
}
// ===== メイン：鍵生成(generateLargePrime) =====
async function loadSmallPrimes() {
    const response = await fetch("https://cdn.jsdelivr.net/gh/Kazuhiro-Tokumoto/rsa@main/primes.bin");
    const buffer = await response.arrayBuffer();
    const view = new Uint32Array(buffer);
    smallPrimesBI = Array.from(view).map(p => BigInt(p));
}
function generateLargePrime(bits) {
    const min = 1n << BigInt(bits - 1);
    const e = 65537n;
    const stepSize = 2000; // 一度にチェックする範囲
    while (true) {
        let pBase = bytesToBigInt(globalThis.crypto.getRandomValues(new Uint8Array(bits / 8))) | 1n | min;
        // 1万個の素数に対する「初期の剰余」を計算
        const initialRems = new Int32Array(smallPrimesBI.length);
        for (let j = 0; j < smallPrimesBI.length; j++) {
            initialRems[j] = Number(pBase % smallPrimesBI[j]);
        }
        // ビットマップ作成 (2000ビット = 32bit型 × 63要素)
        const sieve = new Uint32Array(Math.ceil(stepSize / 32));
        sieve.fill(0xFFFFFFFF); // 最初は全部「素数候補(1)」
        // 1万個の素数で一気にふるいにかける
        for (let j = 0; j < smallPrimesBI.length; j++) {
            const pj = Number(smallPrimesBI[j]);
            let r = initialRems[j];
            // pBase + 2*k が pj で割り切れる場所を 0 にする
            // (pj - r) が偶数なら (pj-r)/2, 奇数なら (2*pj-r)/2 からスタート
            let start = (r === 0) ? 0 : (pj - r);
            if (start % 2 !== 0)
                start += pj;
            start /= 2;
            for (let k = start; k < stepSize; k += pj) {
                sieve[k >> 5] &= ~(1 << (k & 31));
            }
        }
        // 生き残ったビットだけミラー・ラビンへ
        for (let k = 0; k < stepSize; k++) {
            if (sieve[k >> 5] & (1 << (k & 31))) {
                const p = pBase + BigInt(k * 2);
                if ((p - 1n) % e !== 0n) {
                    if (isProbablyPrime(p, 1)) { // 1回だけ判定
                        if (isProbablyPrime(p, 12))
                            return p; // 通れば確定
                    }
                }
            }
        }
    }
}
// ===== Worker Message Handler =====
self.onmessage = async (e) => {
    try {
        const { bits } = e.data;
        if (smallPrimesBI.length === 0) {
            await loadSmallPrimes();
        }
        const prime = generateLargePrime(bits);
        self.postMessage({ prime: prime.toString() });
    }
    catch (error) {
        self.postMessage({ error: String(error) });
    }
};
