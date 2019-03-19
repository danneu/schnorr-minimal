import * as assert from 'assert'
import { Point, Scalar } from './elliptic'
import { hash } from './sha256'

export const secp256k1 = {
    a: 0x0000000000000000000000000000000000000000000000000000000000000000n,
    b: 0x0000000000000000000000000000000000000000000000000000000000000007n,
    g: {
        x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
        y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
    },
    // order
    n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
    p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
}

// Handles negative quotients.
//
//      -34 % 23 === -11
//      mod(-34, 23) === 12
export function mod(a: bigint, b: bigint): bigint {
    return ((a % b) + b) % b
}

// pows then mods, but uses intermediate mods to keep intermediate number within bigint range
export function powmod(base: bigint, exp: bigint, m: bigint): bigint {
    if (exp === 0n) {
        return 1n
    }
    if (exp % 2n === 0n) {
        return mod(powmod(base, exp / 2n, m) ** 2n, m)
    } else {
        return mod(base * powmod(base, exp - 1n, m), m)
    }
}

export function modInverse(a: bigint, m: bigint): bigint {
    if (a < 0 || m <= a) {
        a = mod(a, m)
    }

    let [c, d] = [a, m]
    let q = d / c
    let [uc, vc, ud, vd] = [1n, 0n, 0n, 1n]

    while (c !== 0n) {
        ;[q, c, d] = [d / c, mod(d, c), c]
        ;[uc, vc, ud, vd] = [ud - q * uc, vd - q * vc, uc, vc]
    }

    // At this point, d is the GCD, and ud*a+vd*m = d.
    // If d == 1, this means that ud is a inverse.
    assert.strictEqual(d, 1n)
    if (ud > 0) {
        return ud
    } else {
        return ud + m
    }
}

function bigIntSqrt(n: bigint): bigint {
    if (n < 0n) {
        throw new Error('cannot sqrt negative number')
    }

    if (n < 2n) {
        return n
    }

    // tslint:disable-next-line: no-shadowed-variable
    function newtonIteration(n: bigint, x0: bigint): bigint {
        const x1 = (n / x0 + x0) >> 1n
        if (x0 === x1 || x0 === x1 - 1n) {
            return x0
        }
        return newtonIteration(n, x1)
    }

    return newtonIteration(n, 1n)
}

export function bufferToHex(buf: Uint8Array): string {
    let result = ''

    for (const b of buf) {
        const value = b.toString(16)
        result += value.length === 1 ? '0' + value : value
    }

    return result
}

export function bufferFromHex(hex: string): Uint8Array {
    if (hex.length % 2 === 1) {
        throw new Error(`hex string had odd length`)
    }
    return new Uint8Array(hex.match(/.{1,2}/g)!.map((byte) => Number.parseInt(byte, 16)))
}

// export function bufferToBigInt(buf: Uint8Array): bigint {
//     return BigInt('0x' + bufferToHex(buf))
// }

export function bufferToBigInt(bytes: Uint8Array): bigint {
    let result = 0n
    const n = bytes.length

    // Read input in 8 byte slices
    if (n >= 8) {
        const view = new DataView(bytes.buffer, bytes.byteOffset)

        for (let i = 0, k = n & ~7; i < k; i += 8) {
            const x = view.getBigUint64(i, false)
            result = (result << 64n) + x
        }
    }

    // Mop up any remaining bytes
    for (let i = n & ~7; i < n; i++) {
        result = result * 256n + BigInt(bytes[i])
    }

    return result
}

// Buffer is fixed-length 32bytes
export function bufferFromBigInt(n: bigint): Uint8Array {
    const out = []
    const base = 256n
    while (n >= base) {
        out.push(Number(n % base))
        n = n / base
    }
    out.push(Number(n))

    if (out.length > 32) {
        throw new Error('bigint overflows 32 byte buffer')
    }

    const buf = new Uint8Array(32)
    buf.set(out.reverse(), 32 - out.length)
    return buf
}

export function concatBuffers(...buffs: Uint8Array[]) {
    let totalSize = 0
    for (const buf of buffs) {
        assert(buf instanceof Uint8Array)
        totalSize += buf.length
    }

    const res = new Uint8Array(totalSize)
    let writeAt = 0
    for (const buf of buffs) {
        res.set(buf, writeAt)
        writeAt += buf.length
    }

    return res
}

// 33 bytes: // first byte represents y, next 32 bytes are x coord
export function pointFromBuffer(buf: Uint8Array): Point {
    if (buf.length !== 33) {
        throw new Error('invalid point buffer')
    }

    if (![0x02, 0x03].includes(buf[0])) {
        throw new Error('not compressed')
    }

    // odd is 1n or 0n
    const odd = BigInt(buf[0] - 0x02)

    const x = bufferToBigInt(buf.slice(1, 33))

    const { p } = secp256k1
    const ysq = (powmod(x, 3n, p) + 7n) % p
    const y0 = powmod(ysq, (p + 1n) / 4n, p)
    if (powmod(y0, 2n, p) !== ysq) {
        throw new Error('point not on curve')
    }
    const y = (y0 & 1n) !== odd ? p - y0 : y0
    return { x, y }
}

export function pointToBuffer(point: Point): Uint8Array {
    // 0x02: y is even
    // 0x03: y is odd
    const b0 = point.y % 2n === 0n ? 0x02 : 0x03

    const xbuf = bufferFromBigInt(point.x)
    assert.equal(xbuf.length, 32)

    const result = new Uint8Array(33)
    result.set([b0], 0)
    result.set(xbuf, 1)

    return result
}

export function constantTimeBufferEquals(a: Uint8Array, b: Uint8Array): boolean {
    const aLen = a.length
    const bLen = b.length
    const len = Math.max(aLen, bLen)
    let result = 0

    for (let i = 0; i < len; i++) {
        result |= a[i % aLen] ^ b[i % bLen]
    }

    result |= aLen ^ bLen

    return result === 0
}

export function utf8ToBuffer(text: string): Uint8Array {
    return new TextEncoder().encode(text)
}

export function isPointOnCurve({ x, y }: Point): boolean {
    const { p, a, b } = secp256k1
    return (y * y - (x * x * x + a * x + b)) % p === 0n
}

export function jacobi(y: bigint): bigint {
    return powmod(y, (secp256k1.p - 1n) / 2n, secp256k1.p)
}

export function getK(R: Point, k0: bigint): bigint {
    return jacobi(R.y) === 1n ? k0 : secp256k1.n - k0
}

export function getK0(privkey: Scalar, message: Uint8Array): Scalar {
    const k0 = bufferToBigInt(hash(concatBuffers(bufferFromBigInt(privkey), message))) % secp256k1.n
    if (k0 === 0n) {
        throw new Error('k0 is zero')
    }
    return k0
}

export function getE(Rx: bigint, P: Point, m: Uint8Array): bigint {
    return bufferToBigInt(hash(concatBuffers(bufferFromBigInt(Rx), pointToBuffer(P), m))) % secp256k1.n
}
