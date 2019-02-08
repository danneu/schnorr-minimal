import * as util from './util'
import PrivateKey from './private-key'
import { Point, multiply, add, INFINITE_POINT } from './elliptic'
import * as assert from 'assert'

export default class PublicKey {
    readonly _point: Point

    static fromPrivateKey(key: PrivateKey): PublicKey {
        const point = multiply(util.secp256k1.g, key._scalar)
        return new PublicKey(point)
    }

    static fromBuffer(buf: Uint8Array): PublicKey {
        // Must be in compressed format
        assert.strictEqual(buf.length, 33)
        return new PublicKey(util.pointFromBuffer(buf))
    }

    static _fromPoint(point: Point): PublicKey {
        // TODO: Ensure point is on curve
        return new PublicKey(point)
    }

    static combine(keys: Array<PublicKey>): PublicKey {
        if (keys.length === 0) {
            throw new Error('must combine at least one public key (array was empty)')
        }
        let result = keys[0]._point
        for (let i = 1; i < keys.length; i++) {
            result = add(result, keys[i]._point)
        }
        if (result === INFINITE_POINT) {
            throw new Error('could not combine public keys (infinite point found)')
        }
        return new PublicKey(result)
    }

    private constructor(point: Point) {
        // Point must already be validated that it's on the curve at this point.
        this._point = point
    }

    multiply(tweak: Uint8Array): PublicKey {
        const scalar = util.bufferToBigInt(tweak)
        const point = multiply(this._point, scalar)
        return new PublicKey(point)
    }

    toBuffer(): Uint8Array {
        return util.pointToBuffer(this._point)
    }
}
