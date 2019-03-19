import * as assert from 'assert'
import { randomFillSync } from 'crypto'
import 'mocha'
import { INFINITE_POINT, pointAdd as add, pointMultiply as multiply } from '../src/elliptic'
import * as util from '../src/util'

describe('elliptic', () => {
    describe('G * order', () => {
        it('is infinite point', () => {
            assert.strictEqual(multiply(util.curve.g, util.curve.n), INFINITE_POINT)
        })
    })

    // 1. Choose two random integers modulo n
    // 2. Compute c=a+b
    // 3. Compute points P=aG, Q=bG, R=cG
    // 4. Verify that P+Q=Q+P=R
    it('works with random scalars', function() {
        this.timeout(5000)

        function randomScalar(): bigint {
            const buf = new Uint8Array(32)
            randomFillSync(buf)
            return util.bufferToBigInt(buf) % util.curve.n
        }

        for (let i = 0; i < 16; i++) {
            const a = randomScalar()
            const b = randomScalar()
            const c = a + b

            const P = multiply(util.curve.g, a)
            const Q = multiply(util.curve.g, b)
            const R = multiply(util.curve.g, c)
            // console.log({ a, b, c, P, Q, R })

            assert.deepStrictEqual(add(P, Q), R)
            assert.deepStrictEqual(add(Q, P), R)
        }
    })
})
