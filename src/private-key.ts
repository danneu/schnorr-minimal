import { secp256k1 as curve, bufferToBigInt, bufferFromBigInt } from './util'

export default class PrivateKey {
    readonly _scalar: bigint

    static fromBuffer(buf: Uint8Array): PrivateKey {
        return new PrivateKey(bufferToBigInt(buf))
    }

    static _fromBigInt(scalar: bigint): PrivateKey {
        return new PrivateKey(scalar)
    }

    private constructor(scalar: bigint) {
        // Centralize validation here so that we cannot create invalid privkeys
        if (scalar <= 0n || scalar >= curve.n) {
            throw new Error('invalid privkey')
        }

        this._scalar = scalar
    }

    toBuffer(): Uint8Array {
        return bufferFromBigInt(this._scalar)
    }

    multiply(tweak: PrivateKey): PrivateKey {
        return new PrivateKey((this._scalar * tweak._scalar) % curve.n)
    }

    add(tweak: PrivateKey): PrivateKey {
        return new PrivateKey((this._scalar + tweak._scalar) % curve.n)
    }
}
