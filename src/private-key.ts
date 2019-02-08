import * as util from './util'

export default class PrivateKey {
    readonly _scalar: bigint

    static fromBuffer(buf: Uint8Array): PrivateKey {
        return new PrivateKey(util.bufferToBigInt(buf))
    }

    static _fromBigInt(scalar: bigint): PrivateKey {
        return new PrivateKey(scalar)
    }

    private constructor(scalar: bigint) {
        // Centralize validation here so that we cannot create invalid privkeys
        if (scalar <= 0n || scalar >= util.secp256k1.n) {
            throw new Error('invalid privkey')
        }

        this._scalar = scalar
    }

    toBuffer(): Uint8Array {
        return util.bufferFromBigInt(this._scalar)
    }
}
