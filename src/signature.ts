import * as assert from 'assert'
import { secp256k1 as curve, powmod, pointFromBuffer, bufferToHex } from './util'
import { jacobi, concatBuffers as concat, bufferToBigInt as int, pointToBuffer, bufferFromBigInt } from './util'
import { pointMultiply, pointSubtract, INFINITE_POINT } from './elliptic'
import { hash } from './sha256'
import { Point } from '.'

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
        return { r, s }
    },
    toBytes({ r, s }: Signature): Uint8Array {
        return concat(bufferFromBigInt(r), bufferFromBigInt(s))
    },
    toHex(sig: Signature): string {
        return bufferToHex(Signature.toBytes(sig))
    },
}

export function sign(message: Uint8Array, secret: bigint): Signature {
    const m = message
    const d = secret
    assert.strictEqual(m.length, 32)
    if (d < 1n || d > curve.n - 1n) {
        throw new Error('secret must 1 <= d <= n-1')
    }
    const k0 = int(hash(concat(bufferFromBigInt(d), m))) % curve.n
    if (k0 === 0n) {
        throw new Error('sig failed')
    }
    const R = pointMultiply(curve.g, k0)

    // nonce
    const k = jacobi(R.y) === 1n ? k0 : curve.n - k0

    // challenge
    const e = int(hash(concat(bufferFromBigInt(R.x), pointToBuffer(pointMultiply(curve.g, d)), m))) % curve.n

    const s = (k + e * d) % curve.n
    const sig = { r: R.x, s }
    return sig
}

export function verify(pubkey: Point, message: Uint8Array, sig: Signature): boolean {
    assert(message.length === 32, 'message must be 32bytes')
    const m = message
    const P = pubkey

    const { r, s } = sig

    // TODO: Centralize validation
    if (r >= curve.p) {
        return false
    }

    if (s >= curve.n) {
        return false
    }

    const e = int(hash(concat(bufferFromBigInt(r), pointToBuffer(P), m))) % curve.n
    const R = pointSubtract(pointMultiply(curve.g, s), pointMultiply(P, e))

    if (R === INFINITE_POINT) {
        return false
    } else if (jacobi(R.y) !== 1n) {
        return false
    } else if (R.x !== r) {
        return false
    } else {
        return true
    }
}
