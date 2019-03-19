import { Point, Scalar, Signature, util } from '.'

// This module exposes functions that:
//
//     - Sanity-check inputs to avoid mistakes
//     - Validate runtime types since lib may be consumed from JS instead of TS
//     - Validate input data / business logic
//
// This module throws CheckError so that check-site can avoid swallowing
// extraneous exceptions.

export class CheckError extends Error {
    constructor(...args: any[]) {
        super(...args)
        Error.captureStackTrace(this, CheckError)
    }
}

// like assert() except it throws CheckError.
//
// Use this instead of manually throwing.
function check(assertion: boolean, message: string) {
    if (!assertion) {
        throw new CheckError(message)
    }
}

// TODO: Add redundant runtime checks for users consuming from JS instead of TS.

export function pubkeysAreUnique(pubkeys: Point[]): Point[] {
    // validate runtime type
    check(Array.isArray(pubkeys), 'pubkeys must be array')
    // validate data
    check(pubkeys.length > 0, 'pubkeys array was empty')
    const seen = new Set()
    for (const pubkey of pubkeys) {
        const serialized = JSON.stringify([pubkey.x, pubkey.y])
        check(!seen.has(serialized), 'pubkeys must be unique')
        seen.add(serialized)
    }

    return pubkeys
}

export function privkeysAreUnique(privkeys: Scalar[]): Scalar[] {
    // validate runtime type
    check(Array.isArray(privkeys), 'privkeys must be array')
    // validate data
    check(privkeys.length > 0, 'privkeys array was empty')
    const seen = new Set()
    for (const privkey of privkeys) {
        const serialized = Scalar.toHex(privkey)
        check(!seen.has(serialized), 'privkeys must be unique')
        seen.add(serialized)
    }
    return privkeys
}

export function checkPrivkey(privkey: Scalar): Scalar {
    // validate runtime type
    check(typeof privkey === 'bigint', 'privkey must be bigint')
    // validate data
    check(privkey >= 1n, 'privkey must be in range 1 to n-1')
    check(privkey <= util.secp256k1.n - 1n, 'privkey must be in range 1 to n-1')
    return privkey
}

export function checkSignature(sig: Signature): Signature {
    // validate runtime type
    check(typeof sig === 'object', 'signature must be object')
    check(typeof sig.r === 'bigint', 'signature.r must be bigint')
    check(typeof sig.s === 'bigint', 'signatuer.s must be bigint')
    // validate data
    check(sig.r < util.secp256k1.p, 'signature.r is greater or equal to curve field size')
    check(sig.s < util.secp256k1.n, 'signature.s is greater or equal to curve order')
    return sig
}

export function checkMessage(message: Uint8Array): Uint8Array {
    // validate runtime type
    check(message instanceof Uint8Array, 'message must be a byte array')
    // validate data
    check(message.length === 32, 'message length must be 32 bytes')
    return message
}

export function checkPubkey(point: Point): Point {
    // validate runtime type
    check(typeof point === 'object', 'pubkey must be object')
    check(typeof point.x === 'bigint', 'pubkey.x must be bigint')
    check(typeof point.y === 'bigint', 'pubkey.y must be bigint')
    // validate data
    // ...
    return point
}
