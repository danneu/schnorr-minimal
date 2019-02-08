import 'mocha'
import * as assert from 'assert'
import * as util from '../src/util'
import PrivateKey from '../src/private-key'

describe('PrivateKey', () => {
    describe('fromBuffer', () => {
        it('works', () => {
            const encoded = util.bufferFromHex(
                'e47d79c74106dbc026a8e672ced54c3f23c7a001a2ef9318be3f338db4edba2d'
            )
            const actual = PrivateKey.fromBuffer(encoded)
            assert.strictEqual(
                actual._scalar,
                0xe47d79c74106dbc026a8e672ced54c3f23c7a001a2ef9318be3f338db4edba2dn
            )
            assert.strictEqual(PrivateKey.fromBuffer(Uint8Array.of(42))._scalar, 42n)
        })
    })

    describe('toBuffer', () => {
        it('roundtrips', () => {
            const encoded = 'e47d79c74106dbc026a8e672ced54c3f23c7a001a2ef9318be3f338db4edba2d'
            const key = PrivateKey.fromBuffer(util.bufferFromHex(encoded))
            assert.strictEqual(util.bufferToHex(key.toBuffer()), encoded)
        })
    })

    it('cannot exceed curve order', () => {
        const scalar = util.secp256k1.n + 1n
        assert.throws(() => PrivateKey._fromBigInt(scalar), /invalid privkey/)
    })
})
