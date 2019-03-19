import * as assert from 'assert'
import { secp256k1 as curve, powmod, pointFromBuffer, bufferToHex } from './util'
import {
    getE,
    getK0,
    getK,
    jacobi,
    concatBuffers as concat,
    bufferToBigInt as int,
    pointToBuffer,
    bufferFromBigInt,
} from './util'
import { pointMultiply, pointSubtract, INFINITE_POINT } from './elliptic'
import { hash } from './sha256'
import { Point } from '.'
import * as check from './check'

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

export function sign(message: Uint8Array, privkey: bigint): Signature {
    assert.strictEqual(message.length, 32)
    check.checkPrivkey(privkey)
    const m = message
    const d = privkey

    const k0 = getK0(d, m)
    if (k0 === 0n) {
        throw new Error('sig failed')
    }
    const R = pointMultiply(curve.g, k0)

    // nonce
    const k = getK(R, k0)

    // challenge
    const e = getE(R.x, Point.fromPrivKey(d), m)

    const s = (k + e * d) % curve.n
    const sig = { r: R.x, s }
    check.checkSignature(sig)
    return sig
}

export function verify(pubkey: Point, message: Uint8Array, sig: Signature): boolean {
    assert(message.length === 32, 'message must be 32bytes')
    const m = message
    const P = pubkey

    try {
        check.checkSignature(sig)
    } catch (err) {
        return false
    }

    const { r, s } = sig
    const e = getE(r, P, m)
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
