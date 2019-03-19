import { Scalar } from '../src'
import * as util from '../src/util'
import * as crypto from 'crypto'
import * as check from '../src/check'

export function randomPrivkey(): Scalar {
    const buf = new Uint8Array(32)
    crypto.randomFillSync(buf)
    const privkey = util.bufferToBigInt(buf) % util.secp256k1.n
    return check.checkPrivkey(privkey)
}

export function randomInt(min: number, max: number): number {
    return Math.floor(Math.random() * (max - min + 1) + min)
}
