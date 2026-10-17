/*
 * EXPERIMENTAL v0.8: synthetic-only XPC data receipt worker.
 * The service cannot open documents, create files, or return payload bytes.
 * No trusted peer/approval assertion: ad-hoc test binaries are not
 * production same-Team-ID identities. Replay cache is process-local ONLY.
 */
#define __STDC_WANT_LIB_EXT1__ 1
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <CommonCrypto/CommonDigest.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BBX_MAX_PAYLOAD 2000
#define BBX_MAX_NONCES 64

static dispatch_queue_t nonceQueue;
static char seen[BBX_MAX_NONCES][33];
static size_t seenCount=0;

static bool lowerHex(const char *s,size_t n){
    if(!s || strnlen(s,n+1)!=n)return false;
    for(size_t i=0;i<n;i++){
        const char c=s[i];
        if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;
    }
    return true;
}
static bool testName(const char *s){
    if(!s)return false;
    size_t n=strnlen(s,80);
    if(n<14||n>64||strncmp(s,"bbx-test-",9)!=0 ||
       strcmp(s+n-4,".txt")!=0)return false;
    for(size_t i=9;i<n-4;i++){
        char c=s[i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||
             (c>='0'&&c<='9')||c=='-'||c=='_'))return false;
    }
    return true;
}
static bool exactKeys(xpc_object_t request){
    __block unsigned count=0;
    __block bool valid=true;
    xpc_dictionary_apply(request,^bool(const char *key,xpc_object_t value){
        (void)value;
        if(strcmp(key,"method")!=0 && strcmp(key,"name")!=0 &&
           strcmp(key,"nonce")!=0 && strcmp(key,"sha256")!=0 &&
           strcmp(key,"payload")!=0)valid=false;
        count++;
        return true;
    });
    return valid && count==5;
}
static bool isType(xpc_object_t request,const char *key,xpc_type_t type){
    xpc_object_t item=xpc_dictionary_get_value(request,key);
    return item && xpc_get_type(item)==type;
}
static bool digestMatches(const void *data,size_t size,const char *claimed){
    unsigned char actual[CC_SHA256_DIGEST_LENGTH];
    if(!CC_SHA256(data,(CC_LONG)size,actual))return false;
    unsigned difference=0;
    const char chars[]="0123456789abcdef";
    for(size_t i=0;i<CC_SHA256_DIGEST_LENGTH;i++){
        difference|=(unsigned char)claimed[2*i] ^
                    (unsigned char)chars[actual[i]>>4];
        difference|=(unsigned char)claimed[2*i+1] ^
                    (unsigned char)chars[actual[i]&15];
    }
    memset_s(actual,sizeof(actual),0,sizeof(actual));
    return difference==0;
}
static void respond(xpc_connection_t peer,xpc_object_t message,const char *status){
    xpc_object_t reply=xpc_dictionary_create_reply(message);
    if(!reply)return;
    xpc_dictionary_set_string(reply,"status",status);
    xpc_connection_send_message(peer,reply);
    xpc_release(reply);
}
static void handle(xpc_connection_t peer,xpc_object_t message){
    if(!exactKeys(message) ||
       !isType(message,"method",XPC_TYPE_STRING) ||
       !isType(message,"name",XPC_TYPE_STRING) ||
       !isType(message,"nonce",XPC_TYPE_STRING) ||
       !isType(message,"sha256",XPC_TYPE_STRING) ||
       !isType(message,"payload",XPC_TYPE_DATA)){
        respond(peer,message,"BAD_REQUEST");
        return;
    }
    const char *method=xpc_dictionary_get_string(message,"method");
    const char *name=xpc_dictionary_get_string(message,"name");
    const char *nonce=xpc_dictionary_get_string(message,"nonce");
    const char *sha=xpc_dictionary_get_string(message,"sha256");
    size_t count=0;
    const void *bytes=xpc_dictionary_get_data(message,"payload",&count);
    if(!method || strcmp(method,"snapshot_receipt")!=0 ||
       !testName(name) || !lowerHex(nonce,32) || !lowerHex(sha,64) ||
       count<1 || count>BBX_MAX_PAYLOAD || !bytes){
        respond(peer,message,"BAD_REQUEST");
        return;
    }
    if(!digestMatches(bytes,count,sha)){
        respond(peer,message,"DIGEST_MISMATCH");
        return;
    }
    // Even concurrent requests with one nonce must not both succeed.
    // Exhaustion fails closed; cache is bounded and NOT durable across restart.
    __block const char *status="REPLAY";
    dispatch_sync(nonceQueue,^{
        for(size_t i=0;i<seenCount;i++)
            if(strcmp(seen[i],nonce)==0)return;
        if(seenCount>=BBX_MAX_NONCES){
            status="CAPACITY_EXHAUSTED";
            return;
        }
        memcpy(seen[seenCount],nonce,33);
        seenCount++;
        status="ACCEPTED";
    });
    respond(peer,message,status);
}
static void acceptPeer(xpc_connection_t peer){
    // No positive code-signing peer requirement in this ad-hoc test fixture.
    // This service has no filesystem mutation permission/API and is NOT a
    // production authorization service.
    xpc_connection_set_event_handler(peer,^(xpc_object_t event){
        if(xpc_get_type(event)==XPC_TYPE_DICTIONARY)handle(peer,event);
    });
    xpc_connection_resume(peer);
}
int main(void){
    nonceQueue=dispatch_queue_create("dev.agentblackbox.synthetic-receipt",DISPATCH_QUEUE_SERIAL);
    xpc_main(acceptPeer);
    return 70;
}
