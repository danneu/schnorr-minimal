import * as crypto from 'crypto'
import { Scalar } from '../src'
import * as check from '../src/check'
import * as util from '../src/util'

export function randomPrivkey(): Scalar {
    const buf = randomBuffer(32)
    const privkey = util.bufferToBigInt(buf) % util.curve.n
    return check.checkPrivkey(privkey)
}

export function randomInt(min: number, max: number): number {
    return Math.floor(Math.random() * (max - min + 1) + min)
}

export function randomBuffer(len: number): Uint8Array {
    const buf = new Uint8Array(len)
    crypto.randomFillSync(buf)
    return buf
}
