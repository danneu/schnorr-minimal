import 'mocha'
import * as assert from 'assert'
import * as util from '../src/util'
import PrivateKey from '../src/private-key'
import PublicKey from '../src/public-key'
import { Point, INFINITE_POINT } from '../src/elliptic'
import { sign, verify } from '../src/signature'

function buffer(hex: string): Uint8Array {
    return util.bufferFromHex(hex)
}

function hex(buf: Uint8Array): string {
    return util.bufferToHex(buf)
}

function int(buf: Uint8Array): bigint {
    return util.bufferToBigInt(buf)
}

describe('signature', () => {
    describe('sign', () => {
        it('works', () => {
            const secret = 0x0000000000000000000000000000000000000000000000000000000000000001n
            const message = buffer('0000000000000000000000000000000000000000000000000000000000000000')
            const expected = buffer(
                '787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF67031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05'
            )
            const sig = sign(message, secret)
            assert.strictEqual(hex(sig), hex(expected))

            const pubkey = buffer('0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798')
            assert(verify(pubkey, message, sig))
        })

        it('passes fixtures', () => {
            const { readFileSync } = require('fs')
            const { join } = require('path')
            const { parse } = require('csv/lib/sync')

            const text = readFileSync(join(__dirname, './fixtures/schnorr-test-vectors.csv'), 'utf8')
            const rows = parse(text)

            for (let [seckey, pubkey, msg, sig, verifies, comment] of rows.slice(1)) {
                seckey = seckey.length ? int(buffer(seckey)) : null
                pubkey = buffer(pubkey)
                msg = buffer(msg)
                sig = buffer(sig.trim())
                verifies = verifies === 'TRUE'

                // test signing
                if (seckey) {
                    const sigActual = sign(msg, seckey)
                    assert.strictEqual(hex(sigActual), hex(sig))
                }

                // test verifying
                const actualVerifies = verify(pubkey, msg, sig)
                assert.strictEqual(actualVerifies, verifies)
            }
        })
    })
})
