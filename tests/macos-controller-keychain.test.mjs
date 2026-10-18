import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createEphemeralMacControllerSigner,encodeMacReviewedRsaHandoff}
  from '../src/macos-reviewed-signed-authority.mjs';
import {
  parseMacKeychainPublicRecord,encodeMacKeychainUnsignedReview,
  validateMacKeychainSignedReview
} from '../src/macos-controller-keychain.mjs';
import {fixedMacReviewedVector,FIXED_ISSUED}
  from '../examples/mcp-macos-reviewed-contract-vector.mjs';

const contents=path=>readFileSync(new URL('../'+path,import.meta.url),'utf8');
const pubRecord=key=>{
  const der=key.export({type:'pkcs1',format:'der'});
  return 'BBX_CONTROLLER_RSA_PUBLIC_PKCS1_BASE64='+der.toString('base64')+'\n';
};
test('separate Keychain RSA public enrollment requires one exact public record',()=>{
  const pair=createEphemeralMacControllerSigner();
  const enrolled=parseMacKeychainPublicRecord(pubRecord(pair.publicKey));
  assert.equal(enrolled.sha256.length,64);
  assert.equal(enrolled.publicKey.asymmetricKeyType,'rsa');
  assert.ok(Object.isFrozen(enrolled));
  for(const bad of [
    '',null,undefined,'BBX_KEYCHAIN_CONTROLLER_PROVISIONED\n',
    pubRecord(pair.publicKey)+'extra',
    pubRecord(pair.publicKey).replace(/\n$/,''),
    pubRecord(pair.publicKey).replace('BASE64=','BASE64= '),
    'BBX_CONTROLLER_RSA_PUBLIC_PKCS1_BASE64=Zm9v\n',
    'BBX_CONTROLLER_RSA_PUBLIC_PKCS1_BASE64=****\n',
    'BBX_CONTROLLER_RSA_PUBLIC_PKCS1_BASE64=Zm9v===\n'
  ])assert.throws(()=>parseMacKeychainPublicRecord(bad));
});
test('Keychain-issued synthetic review binds fixed fields and HMAC audit with independently pinned RSA',()=>{
  const first=createEphemeralMacControllerSigner();
  const foreign=createEphemeralMacControllerSigner();
  const tx=fixedMacReviewedVector();
  const checkpoint='b'.repeat(64);
  const input=encodeMacKeychainUnsignedReview(tx,{
    reservationMac:checkpoint,now:FIXED_ISSUED
  });
  assert.ok(input.toString('ascii').endsWith('reservationMac='+checkpoint+'\n'));
  assert.ok(!input.toString('ascii').includes('controllerSig='));
  const pinned=parseMacKeychainPublicRecord(pubRecord(first.publicKey));
  const wire=encodeMacReviewedRsaHandoff(tx,{
    privateKey:first.privateKey,reservationMac:checkpoint,now:FIXED_ISSUED
  });
  assert.deepEqual(validateMacKeychainSignedReview(wire,{
    publicKey:pinned.publicKey,transaction:tx,reservationMac:checkpoint,
    now:FIXED_ISSUED
  }),wire);
  const wrong=encodeMacReviewedRsaHandoff(tx,{
    privateKey:foreign.privateKey,reservationMac:checkpoint,now:FIXED_ISSUED
  });
  for(const invalid of [
    wrong,wire.subarray(0,-1),Buffer.concat([wire,Buffer.from('\n')]),
    Buffer.from(wire.toString('ascii').replace(
      'reservationMac='+checkpoint,'reservationMac='+'c'.repeat(64))),
    Buffer.alloc(1537)
  ])assert.throws(()=>validateMacKeychainSignedReview(invalid,{
    publicKey:pinned.publicKey,transaction:tx,reservationMac:checkpoint,
    now:FIXED_ISSUED
  }));
  for(const bad of ['X'.repeat(64),'b'.repeat(63),'',null,undefined])
    assert.throws(()=>encodeMacKeychainUnsignedReview(tx,{
      reservationMac:bad,now:FIXED_ISSUED
    }));
});
test('Keychain signer never emits private key material, provisions only explicitly, and fails on absent enrollment',()=>{
  const code=contents('native/macos/xpc/KeychainControllerSigner.m');
  const cli=contents('examples/mcp-macos-controller-keychain.mjs');
  const runner=contents('examples/mcp-macos-xpc-native-reviewed.mjs');
  const ci=contents('.github/workflows/ci.yml');
  const packageFile=JSON.parse(contents('package.json'));
  for(const symbol of [
    'SecItemCopyMatching','SecKeyCreateRandomKey',
    'SecKeyCreateSignature','SecKeyCopyPublicKey',
    'SecKeyCopyExternalRepresentation(publicKey',
    'kSecAttrIsExtractable:@NO',
    'kSecAttrIsSensitive:@YES',
    'bbx_parse_preissued_review',
    'strcmp(argv[1],"provision")',
    'strcmp(argv[1],"public")',
    'strcmp(argv[1],"sign")',
    'kSecKeyAlgorithmRSASignatureMessagePSSSHA256'
  ])assert.ok(code.includes(symbol),symbol);
  assert.doesNotMatch(code,/SecKeyCopyExternalRepresentation\(privateKey/);
  assert.doesNotMatch(code,/SecKeyCreateSignature\([^]*\bsha256=bad\b/);
  assert.match(code,/if\(existing\)\{CFRelease\(existing\);return 86;\}/);
  assert.match(code,/if\(found!=errSecItemNotFound\)return 87/);
  assert.ok(cli.includes("['provision']"));
  assert.ok(cli.includes("['public']"));
  assert.ok(!runner.includes("['provision']"));
  assert.ok(runner.includes("mode==='handoff-rsa-keychain'"));
  assert.ok(runner.includes('readMacKeychainControllerIdentity(helper)'));
  assert.ok(runner.includes('signMacKeychainReviewedTransaction(helper,transaction'));
  assert.ok(runner.includes('formatPinnedMacRsaPublicHeader(enrolled.publicKey)'));
  assert.ok(runner.includes('if(privateKey!==null&&signController!==null)'));
  assert.ok(ci.includes('native/macos/xpc/KeychainControllerSigner.m'));
  assert.ok(ci.includes('no Keychain identity created on CI'));
  assert.equal(packageFile.scripts['mcp:mac-controller-key'],
    'node examples/mcp-macos-controller-keychain.mjs');
});
