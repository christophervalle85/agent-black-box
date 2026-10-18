/**
 * Fixed-public-data cross-language contract vector (Node vs native C).
 * This checksum is NOT an operator approval, key, or transferable grant.
 */
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  createCanonicalMacReviewedTransaction,encodeCanonicalMacReviewedHandoff
} from '../src/macos-reviewed-transaction.mjs';

export const FIXED_BYTES=Buffer.from('BBX synthetic Touch ID reviewed bytes.\n');
export const FIXED_REVIEW_ID='123e4567-e89b-42d3-a456-426614174000';
export const FIXED_NONCE='abcdef12-3456-4789-8abc-123456789abc';
export const FIXED_ISSUED=1790000000000;
export function fixedMacReviewedVector(){
  return createCanonicalMacReviewedTransaction({
    reviewId:FIXED_REVIEW_ID,
    intent:{
      version:1,operation:'import',noteName:'bbx-test-reviewed.txt',
      byteLength:FIXED_BYTES.length,
      sha256:createHash('sha256').update(FIXED_BYTES).digest('hex'),
      nonce:FIXED_NONCE,
      issuedAt:FIXED_ISSUED,expiresAt:FIXED_ISSUED+60000
    }
  },{now:FIXED_ISSUED});
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  if(process.argv.length===2)console.log(fixedMacReviewedVector().transactionId);
  else if(process.argv.length===3 && process.argv[2]==='--handoff')
    process.stdout.write(encodeCanonicalMacReviewedHandoff(
      fixedMacReviewedVector(),{now:FIXED_ISSUED}
    ));
  else process.exitCode=90;
}
