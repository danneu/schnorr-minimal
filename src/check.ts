import { Point, Scalar, Signature } from '.'
import * as util from './util'
import * as assert from 'assert'

export function pubkeysAreUnique(pubkeys: Point[]): Point[] {
    assert(pubkeys.length > 0, 'pubkeys array was empty')
    const seen = new Set()
    for (const pubkey of pubkeys) {
        const serialized = JSON.stringify([pubkey.x, pubkey.y])
        if (seen.has(serialized)) {
            throw new Error('pubkeys must be unique')
        }
        seen.add(serialized)
    }

    return pubkeys
}

export function privkeysAreUnique(privkeys: Scalar[]): Scalar[] {
    assert(privkeys.length > 0, 'privkeys array was empty')
    const seen = new Set()
    for (const privkey of privkeys) {
        const serialized = Scalar.toHex(privkey)
        if (seen.has(serialized)) {
            throw new Error('privkeys must be unique')
        }
        seen.add(serialized)
    }
    return privkeys
}

export function checkPrivkey(privkey: Scalar): Scalar {
    if (privkey < 1n || privkey > util.secp256k1.n - 1n) {
        throw new Error('privkey must 1 <= privkey <= n-1')
    }
    return privkey
}

export function checkSignature(sig: Signature): Signature {
    if (sig.r >= util.secp256k1.p) {
        throw new Error('r is >= curve field size')
    }
    if (sig.s >= util.secp256k1.n) {
        throw new Error('s is >= curve order')
    }
    return sig
}
