/**
 * v0.8 Phase 5: OPT-IN synthetic transfer review controller adapter.
 * Not a native file transfer, OS entitlement or proof of operator identity.
 * Only in-process trusted host code can create or consume a review. A
 * separate, same-origin UI can decide; a remote model cannot issue requests.
 */
import {randomUUID} from 'node:crypto';
import {createMacTransferReviewPair} from './macos-transfer-review.mjs';

export function createAuditedMacTransferController({store,clock=Date.now}={}) {
  if(!store || typeof store.verify!=='function' || typeof store.add!=='function')
    throw Error('Verified HMAC audit store is required.');
  const queue=createMacTransferReviewPair({clock});
  const audit=(review,ruleId,decision,outcome,summary)=>{
    const intent=review.intent;
    const event={
      id:randomUUID(),timestamp:new Date(clock()).toISOString(),
      runId:'mac-transfer-v0.8',agentId:'trusted-local-host',
      source:'mac-transfer-synthetic',tool:'mac.transfer.'+intent.operation,
      input:'Synthetic '+intent.operation+' '+intent.noteName+'; bytes omitted',
      decision,risk:'high',riskScore:75,ruleId,
      reason:summary,outcome,summary,durationMs:0,
      approvalId:review.reviewId
    };
    return store.add(event);
  };
  const host=Object.freeze({
    request(intent){
      store.verify();
      const review=queue.host.request(intent);
      try{
        audit(review,'MAC_TRANSFER_REVIEW','review','pending',
          'Synthetic transfer review opened; no file operation permitted.');
      }catch(error){
        queue.host.cancel(review.reviewId);
        throw error;
      }
      return review;
    },
    consume({reviewId,intent,bytes}={}){
      store.verify();
      const review=queue.controller.lookup(reviewId);
      if(!review)throw Error('No unconsumed transfer approval.');
      audit(review,'MAC_TRANSFER_CONSUMPTION_ATTEMPT','review','pending',
        'Staged transfer validation requested; no native file access.');
      let result;
      try {
        result=queue.host.consume({reviewId,intent,bytes});
      } catch(error) {
        // The review has already been burned. Record a definitive denial,
        // never leave a forged/altered attempt looking like success.
        audit(review,'MAC_TRANSFER_CONSUMPTION_DENIED','block','blocked',
          'Synthetic approval or payload validation denied; no OS transfer.');
        throw error;
      }
      audit(review,'MAC_TRANSFER_CONSUMED','allow','simulated',
        'One-time synthetic grant validated; no OS transfer occurred.');
      return result;
    },
    cancel(id){
      store.verify();
      const review=queue.controller.lookup(id);
      if(!review)return false;
      audit(review,'MAC_TRANSFER_CANCEL_REQUEST','review','pending',
        'Synthetic transfer cancellation requested.');
      const result=queue.host.cancel(id);
      if(result) audit(review,'MAC_TRANSFER_CANCELLED','block','blocked',
        'Synthetic transfer cancelled; no file operation occurred.');
      return result;
    }
  });
  const controller=Object.freeze({
    pending(){
      store.verify();
      return queue.controller.pending();
    },
    decide(id,decision){
      store.verify();
      if(decision!=='approve'&&decision!=='deny')return false;
      const review=queue.controller.lookup(id);
      if(!review || !queue.controller.pending().some(x=>x.reviewId===id))return false;
      audit(review,'MAC_TRANSFER_DECISION_REQUEST','review','pending',
        'Local UI requested a synthetic review decision.');
      if(!queue.controller.decide(id,decision))return false;
      try{
        audit(review,decision==='approve'?'MAC_TRANSFER_APPROVED':'MAC_TRANSFER_DENIED',
          decision==='approve'?'allow':'block',
          decision==='approve'?'pending':'blocked',
          decision==='approve'
            ?'Operator approved one-time staging; no native file access.'
            :'Operator denied synthetic transfer; no native file access.');
      }catch(error){
        queue.host.cancel(id);
        throw error;
      }
      return true;
    },
    close(){queue.controller.close();}
  });
  return Object.freeze({host,controller});
}
