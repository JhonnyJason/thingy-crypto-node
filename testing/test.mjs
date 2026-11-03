import { test } from "node:test"
import assert from "node:assert/strict"
import * as secUtl from "../output/node_modules/secret-manager-crypto-utils/index.js"
import { ThingyCryptoNode as LegacyNode } from "thingy-crypto-node-legacy" // the published thingy-crypto-node 0.0.2 (smcu 0.3.1)
import { ThingyCryptoNode } from "../output/index.js"

const newNode = async (context) => new ThingyCryptoNode({ ...(await secUtl.createKeyPair()), context })
const A = await newNode()
const B = await newNode()
const content = "hello ThingyCryptoNode ✓"
const dhArgs = ["salt", 1700000000]
// the same keys running 0.0.2
const legacyOf = (n, context) => new LegacyNode({ secretKeyHex: n.key, publicKeyHex: n.id, context })
const LA = legacyOf(A)
const LB = legacyOf(B)

test("constructor: default and custom context", async () => {
    assert.equal(A.ctx, "standard ThingyCryptoNode")
    assert.equal((await newNode("mine")).ctx, "mine")
})

test("verify is gone - old calls fail loudly", () => {
    assert.equal(A.verify, undefined)
    assert.throws(() => A.verify("00", content), TypeError)
})

test("sign + sigCheck", async () => {
    const sig = await A.sign(content)
    assert.equal(await A.sigCheck(sig, content), undefined)
    assert.equal(await A.sigCheck(sig, content + "x"), "Invalid signature!")
    assert.equal(await B.sigCheck(sig, content), "Invalid signature!")
    assert.equal(await A.sigCheck("zz", content), "Malformed input!")
    assert.ok(A.sigCheck(sig, content), "forgotten await is truthy -> fails closed")
})

test("encrypt + decrypt", async () => {
    const secrets = await A.encrypt(content)
    assert.deepEqual(Object.keys(secrets).sort(), ["encryptedContentHex", "referencePointHex"])
    assert.equal(await A.decrypt(secrets), content)
    await assert.rejects(B.decrypt(secrets), /Decryption failed!/)
})

test("diffieHellmanFor: both sides agree, salt/timestamp/context separate", async () => {
    const ab = await A.diffieHellmanFor(B.id, ...dhArgs)
    assert.equal(ab, await B.diffieHellmanFor(A.id, ...dhArgs))
    assert.equal(ab.length, 128)
    assert.notEqual(ab, await A.diffieHellmanFor(B.id, "salt2", 1700000000))
    assert.notEqual(ab, await A.diffieHellmanFor(B.id, "salt", 1700000001))
    const C = new ThingyCryptoNode({ secretKeyHex: A.key, publicKeyHex: A.id, context: "other" })
    assert.notEqual(ab, await C.diffieHellmanFor(B.id, ...dhArgs))
})

// --- compatibility with the published thingy-crypto-node 0.0.2 ---

test("legacy: signatures interoperate both ways", async () => {
    const oldSig = await LA.sign(content)
    assert.equal(oldSig, await A.sign(content), "same signature bytes")
    assert.equal(await A.sigCheck(oldSig, content), undefined)
    assert.equal(await LA.verify(await A.sign(content), content), true, "legacy node accepts our signatures")
    assert.equal(await LB.verify(await A.sign(content), content), false)
})

test("legacy: verifyLegacy behaves like 0.0.2 verify", async () => {
    const sig = await A.sign(content)
    for (const [node, oldNode, s, c] of [[A, LA, sig, content], [A, LA, sig, content + "x"], [B, LB, sig, content]])
        assert.equal(await node.verifyLegacy(s, c), await oldNode.verify(s, c))
    assert.equal(await A.verifyLegacy("zz", content), false, "malformed -> false, no throw")
})

test("legacy: decryptLegacy reads 0.0.2 data, decrypt does not", async () => {
    const oldSecrets = await LA.encrypt(content)
    assert.equal(await A.decryptLegacy(oldSecrets), content)
    await assert.rejects(A.decrypt(oldSecrets))
    await assert.rejects(B.decryptLegacy(oldSecrets))
    // migration snippet from the README
    let migrated
    try { migrated = await A.decrypt(oldSecrets) }
    catch { migrated = await A.decryptLegacy(oldSecrets) }
    assert.equal(await A.decrypt(await A.encrypt(migrated)), content)
})

test("legacy: new ciphertext is not readable by 0.0.2", async () => {
    await assert.rejects(async () => LA.decrypt(await A.encrypt(content)))
})

test("legacy: diffieHellmanForLegacy matches a 0.0.2 peer, diffieHellmanFor does not", async () => {
    const legacyPeer = await LB.diffieHellmanFor(A.id, ...dhArgs)
    assert.equal(await A.diffieHellmanForLegacy(B.id, ...dhArgs), legacyPeer)
    assert.equal(await B.diffieHellmanForLegacy(A.id, ...dhArgs), await LA.diffieHellmanFor(B.id, ...dhArgs))
    assert.notEqual(await A.diffieHellmanFor(B.id, ...dhArgs), legacyPeer)
    // custom context
    const C = new ThingyCryptoNode({ secretKeyHex: A.key, publicKeyHex: A.id, context: "mine" })
    assert.equal(await C.diffieHellmanForLegacy(B.id, ...dhArgs), await legacyOf(B, "mine").diffieHellmanFor(A.id, ...dhArgs))
})
