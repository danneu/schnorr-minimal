import 'mocha'
import * as assert from 'assert'
import { hash } from '../src/sha256'
import { bufferToHex as hex } from '../src/util'

// TODO: test hmac

describe('sha256', () => {
    it('hashes empty input', () => {
        const input = new Uint8Array(0)
        assert.strictEqual(hex(hash(input)), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    })

    it('works', () => {
        const input = new TextEncoder().encode('abc')
        assert.strictEqual(hex(hash(input)), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
    })
})
