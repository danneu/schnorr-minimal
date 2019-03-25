import * as assert from 'assert'
import { Point, pointAdd } from '.'
import * as check from './check'
import { INFINITE_POINT, pointEq, pointMultiply, pointSubtract } from './elliptic'
import {
    bufferFromBigInt,
    bufferFromHex,
    bufferToBigInt,
    bufferToBigInt as int,
    bufferToHex,
    concatBuffers as concat,
    curve,
    getE,
    getK,
    getK0,
    jacobi,
    powmod,
} from './util'

// Schnorr Signatures
//
// https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki

export type Signature = {
    r: bigint // i.e. R.x
    s: bigint
}

export const Signature = {
    fromBytes(buf: Uint8Array): Signature {
        assert(buf.length === 64, 'encoded signature must be 64 bytes')
        const r = int(buf.slice(0, 32))
        const s = int(buf.slice(32, 64))
        // TODO: checkSignature here or just let bad sigs fail in verify()?
        return { r, s }
    },
    fromHex(hex: string): Signature {
        return Signature.fromBytes(bufferFromHex(hex))
    },
    toBytes({ r, s }: Signature): Uint8Array {
        return concat(bufferFromBigInt(r), bufferFromBigInt(s))
    },
    toHex(sig: Signature): string {
        return bufferToHex(Signature.toBytes(sig))
    },
}

export function sign(message: Uint8Array, privkey: bigint): Signature {
    check.checkMessage(message)
    check.checkPrivkey(privkey)
    const m = message
    const d = privkey

    const k0 = getK0(d, m)
    const R = pointMultiply(curve.g, k0)
    const k = getK(R, k0) // nonce
    const e = getE(R.x, Point.fromPrivKey(d), m) // challenge
    const s = (k + e * d) % curve.n
    const sig = { r: R.x, s }
    check.checkSignature(sig)
    return sig
}

export function verify(pubkey: Point, message: Uint8Array, sig: Signature): boolean {
    try {
        check.checkPubkey(pubkey)
        check.checkMessage(message)
        check.checkSignature(sig)
    } catch (err) {
        if (err instanceof check.CheckError) {
            return false
        } else {
            throw err
        }
    }

    if (sig.r === 0n || sig.s === 0n) {
        return false
    }

    const m = message
    const P = pubkey

    const e = getE(sig.r, P, m)
    const R = pointSubtract(pointMultiply(curve.g, sig.s), pointMultiply(P, e))

    if (R === INFINITE_POINT) {
        return false
    } else if (jacobi(R.y) !== 1n) {
        return false
    } else if (R.x !== sig.r) {
        return false
    } else {
        return true
    }
}

// https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#Batch_Verification
export function batchVerify(pubkeys: Point[], messages: Uint8Array[], signatures: Signature[]): boolean {
    assert.strictEqual(pubkeys.length, messages.length, 'input arrays must be same length')
    assert.strictEqual(messages.length, signatures.length, 'input arrays must be same length')
    assert.ok(pubkeys.length > 0, 'input arrays must not be empty')

    let leftSide = 0n
    let rightSide = INFINITE_POINT

    for (let i = 0; i < pubkeys.length; i++) {
        const P = pubkeys[i]
        const sig = signatures[i]
        const msg = messages[i]
        // fail fast on invalid inputs
        try {
            check.checkPubkey(P)
            check.checkMessage(msg)
            check.checkSignature(sig)
        } catch (err) {
            if (err instanceof check.CheckError) {
                return false
            } else {
                throw err
            }
        }
        const { r, s } = sig
        const e = getE(r, P, msg)
        const c = (r ** 3n + 7n) % curve.p
        const y = powmod(c, (curve.p + 1n) / 4n, curve.p)
        if (c !== powmod(y, 2n, curve.p)) {
            return false
        }
        const R = { x: r, y }

        if (i === 0) {
            leftSide = leftSide + s
            rightSide = pointAdd(R, pointMultiply(P, e))
        } else {
            const a = randomA()
            leftSide = leftSide + a * s
            rightSide = pointAdd(rightSide, pointMultiply(R, a), pointMultiply(P, a * e))
        }
    }

    return pointEq(pointMultiply(curve.g, leftSide % curve.n), rightSide)
}

function randomA(): bigint {
    let a

    do {
        const buf = new Uint8Array(32)
        if (typeof window === 'undefined') {
            // in node
            require('crypto').randomFillSync(buf)
        } else {
            // in browser
            window.crypto.getRandomValues(buf)
        }

        a = bufferToBigInt(buf) % curve.n
    } while (a < 1n || a > curve.n - 1n)

    return a
}
