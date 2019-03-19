import * as assert from 'assert'
import 'mocha'
import * as util from '../src/util'

describe('bufferFromHex', () => {
    it('fails on odd length', () => {
        assert.throws(() => util.bufferFromHex('000'), /odd length/)
    })

    it('roundtrips', () => {
        for (const hex of [
            '00',
            '01',
            'deadbeef',
            '893aba425419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7',
        ]) {
            assert.strictEqual(util.bufferToHex(util.bufferFromHex(hex)), hex)
        }
    })
})

describe('bufferFromBigInt', () => {
    it('roundtrips', () => {
        for (const n of [
            0n,
            1n,
            0xdeadbeefn,
            0x893aba425419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7n,
        ]) {
            assert.strictEqual(util.bufferToBigInt(util.bufferFromBigInt(n)), n)
        }
    })
})
