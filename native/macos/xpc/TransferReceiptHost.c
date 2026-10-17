/*
 * EXPERIMENTAL test-only ad-hoc XPC host. Sends bounded compiled-in bytes.
 * No OS file selections, no user data, no approvals, no persistent writes.
 * A production host MUST verify the signed worker and operator approval;
 * this host deliberately does neither and cannot claim that trust boundary.
 */
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <CommonCrypto/CommonDigest.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

static void randomNonce(char output[33]){
    unsigned char data[16];
    const char chars[]="0123456789abcdef";
    arc4random_buf(data,sizeof(data));
    for(size_t i=0;i<sizeof(data);i++){
        output[2*i]=chars[data[i]>>4];
        output[2*i+1]=chars[data[i]&15];
    }
    output[32]='\0';
}
static void digest(const unsigned char *data,size_t n,char output[65]){
    unsigned char raw[CC_SHA256_DIGEST_LENGTH];
    const char chars[]="0123456789abcdef";
    CC_SHA256(data,(CC_LONG)n,raw);
    for(size_t i=0;i<CC_SHA256_DIGEST_LENGTH;i++){
        output[2*i]=chars[raw[i]>>4];
        output[2*i+1]=chars[raw[i]&15];
    }
    output[64]='\0';
}
static bool request(xpc_connection_t peer,const char *nonce,const char *sha,
                    const unsigned char *payload,size_t n,const char *expected){
    xpc_object_t message=xpc_dictionary_create(NULL,NULL,0);
    if(!message)return false;
    xpc_dictionary_set_string(message,"method","snapshot_receipt");
    xpc_dictionary_set_string(message,"name","bbx-test-xpc-payload.txt");
    xpc_dictionary_set_string(message,"nonce",nonce);
    xpc_dictionary_set_string(message,"sha256",sha);
    xpc_dictionary_set_data(message,"payload",payload,n);
    xpc_object_t reply=xpc_connection_send_message_with_reply_sync(peer,message);
    xpc_release(message);
    if(!reply || xpc_get_type(reply)!=XPC_TYPE_DICTIONARY){
        if(reply)xpc_release(reply);
        return false;
    }
    const char *got=xpc_dictionary_get_string(reply,"status");
    const bool okay=got && strcmp(got,expected)==0;
    xpc_release(reply);
    return okay;
}
int main(int argc,const char *argv[]){
    if(argc!=2 || (strcmp(argv[1],"valid")!=0 &&
                   strcmp(argv[1],"tamper")!=0 &&
                   strcmp(argv[1],"replay")!=0)){
        puts("BBX_XPC_RECEIPT_INVALID_ARGS");
        return 90;
    }
    const unsigned char payload[]="BBX synthetic XPC transfer bytes.\n";
    const size_t size=sizeof(payload)-1;
    char nonce[33],sha[65];
    randomNonce(nonce);
    digest(payload,size,sha);
    xpc_connection_t peer=xpc_connection_create(
        "dev.agentblackbox.xpc-snapshot-receipt.worker",
        dispatch_get_global_queue(QOS_CLASS_DEFAULT,0));
    if(!peer)return 70;
    xpc_connection_set_event_handler(peer,^(xpc_object_t event){
        (void)event;
    });
    xpc_connection_resume(peer);
    bool correct=false;
    const bool validMode=strcmp(argv[1],"valid")==0;
    const bool replayMode=strcmp(argv[1],"replay")==0;
    if(validMode){
        correct=request(peer,nonce,sha,payload,size,"ACCEPTED");
    }else if(replayMode){
        correct=request(peer,nonce,sha,payload,size,"ACCEPTED") &&
                request(peer,nonce,sha,payload,size,"REPLAY");
    }else{
        unsigned char tampered[sizeof(payload)-1];
        memcpy(tampered,payload,size);
        tampered[0]^=1;
        // Worker MUST reject bad digest and not consume this nonce.
        correct=request(peer,nonce,sha,tampered,size,"DIGEST_MISMATCH") &&
                request(peer,nonce,sha,payload,size,"ACCEPTED");
    }
    xpc_connection_cancel(peer);
    xpc_release(peer);
    if(!correct){
        puts("BBX_XPC_RECEIPT_NOT_ACCEPTED");
        return 87;
    }
    if(validMode)puts("BBX_XPC_RECEIPT_VALID_ACCEPTED");
    else if(replayMode)puts("BBX_XPC_RECEIPT_REPLAY_BLOCKED");
    else puts("BBX_XPC_RECEIPT_TAMPER_BLOCKED");
    return 0;
}
