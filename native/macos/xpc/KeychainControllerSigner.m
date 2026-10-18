/*
 * TEST-ONLY v0.8: explicitly provisioned, persistent macOS Keychain RSA
 * controller identity. No private-key PEM, passphrase, or private bytes are
 * returned to Node or placed in the native signed host.
 *
 * This is a software Keychain credential, NOT a Secure Enclave RSA key or a
 * production controller authorization service. A same-user process that can
 * invoke this diagnostic helper may request signatures. A separate trusted
 * consent authority and independent pin deployment are still required.
 *
 * "provision" refuses to replace an existing key. "public" and "sign"
 * NEVER provision one. Sign accepts ONLY an exact fixed synthetic import
 * review plus a bounded audit checkpoint, not arbitrary caller bytes.
 */
#define __STDC_WANT_LIB_EXT1__ 1
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "ReviewedTransactionHandoff.h"

static NSString *const kKeyTag=@"dev.agentblackbox.test.controller.rsa-pss-v1";
static NSData *tagData(void){
    return [kKeyTag dataUsingEncoding:NSUTF8StringEncoding];
}
static SecKeyRef findPrivateKey(OSStatus *result){
    NSDictionary *lookup=@{
        (id)kSecClass:(id)kSecClassKey,
        (id)kSecAttrApplicationTag:tagData(),
        (id)kSecAttrKeyType:(id)kSecAttrKeyTypeRSA,
        (id)kSecAttrKeyClass:(id)kSecAttrKeyClassPrivate,
        (id)kSecReturnRef:@YES,
        (id)kSecMatchLimit:(id)kSecMatchLimitOne
    };
    SecKeyRef key=NULL;
    const OSStatus status=SecItemCopyMatching((CFDictionaryRef)lookup,
                                               (CFTypeRef *)&key);
    if(result)*result=status;
    return status==errSecSuccess?key:NULL;
}
static bool validRsa2048(SecKeyRef key){
    if(!key)return false;
    CFDictionaryRef attrs=SecKeyCopyAttributes(key);
    if(!attrs)return false;
    NSDictionary *data=(NSDictionary *)attrs;
    const bool valid=[data[(id)kSecAttrKeyType] isEqual:(id)kSecAttrKeyTypeRSA] &&
        [data[(id)kSecAttrKeySizeInBits] integerValue]==2048;
    CFRelease(attrs);
    return valid;
}
static int provision(void){
    OSStatus found=errSecSuccess;
    SecKeyRef existing=findPrivateKey(&found);
    if(existing){CFRelease(existing);return 86;} // never overwrite
    if(found!=errSecItemNotFound)return 87;
    NSDictionary *privateAttrs=@{
        (id)kSecAttrIsPermanent:@YES,
        (id)kSecAttrApplicationTag:tagData(),
        (id)kSecAttrIsSensitive:@YES,
        (id)kSecAttrIsExtractable:@NO
    };
    NSDictionary *attrs=@{
        (id)kSecAttrKeyType:(id)kSecAttrKeyTypeRSA,
        (id)kSecAttrKeySizeInBits:@2048,
        (id)kSecPrivateKeyAttrs:privateAttrs
    };
    CFErrorRef error=NULL;
    SecKeyRef key=SecKeyCreateRandomKey((CFDictionaryRef)attrs,&error);
    if(error)CFRelease(error);
    if(!key)return 87;
    const bool valid=validRsa2048(key);
    CFRelease(key);
    if(!valid)return 87;
    puts("BBX_KEYCHAIN_CONTROLLER_PROVISIONED");
    return 0;
}
static int exportPublic(void){
    OSStatus found=errSecSuccess;
    SecKeyRef privateKey=findPrivateKey(&found);
    if(!privateKey)return 87; // No automatic regeneration.
    if(!validRsa2048(privateKey)){CFRelease(privateKey);return 87;}
    SecKeyRef publicKey=SecKeyCopyPublicKey(privateKey);
    CFRelease(privateKey);
    if(!publicKey)return 87;
    CFErrorRef error=NULL;
    CFDataRef der=SecKeyCopyExternalRepresentation(publicKey,&error);
    CFRelease(publicKey);
    if(error)CFRelease(error);
    if(!der)return 87;
    NSData *bytes=(NSData *)der;
    const bool valid=[bytes length]>=200&&[bytes length]<=512;
    NSString *encoded=valid?[bytes base64EncodedStringWithOptions:0]:nil;
    if(valid&&encoded)
        printf("BBX_CONTROLLER_RSA_PUBLIC_PKCS1_BASE64=%s\n",
               [encoded UTF8String]);
    CFRelease(der);
    return valid&&encoded?0:87;
}
static int signFixedSyntheticReview(void){
    /* A bounded stdin record has the exact canonical fields and a single
       trailing reservationMac=64-lowercase-hex line; no other fields. */
    char source[900]={0};
    size_t used=0;
    for(;;){
        const int c=fgetc(stdin);
        if(c==EOF)break;
        if(used>=sizeof(source)-1||
           (c!='\n'&&(c<0x20||c>0x7e)))return 87;
        source[used++]=(char)c;
    }
    if(ferror(stdin)||!used)return 87;
    source[used]='\0';
    char *reservation=strstr(source,"reservationMac=");
    if(!reservation||reservation==source)return 87;
    const size_t canonicalLength=(size_t)(reservation-source);
    const size_t resLength=sizeof("reservationMac=")-1+64+1;
    if(canonicalLength<1||canonicalLength>=768||
       source[canonicalLength-1]!='\n'||
       used-canonicalLength!=resLength||
       reservation[resLength-1]!='\n')return 87;
    char mac[65]={0};
    memcpy(mac,reservation+sizeof("reservationMac=")-1,64);
    if(!bbx_reviewed_lowerhex(mac,64))return 87;
    char canonical[768]={0};
    memcpy(canonical,source,canonicalLength);
    BBXPreissuedReview review={0};
    if(!bbx_parse_preissued_review(canonical,canonicalLength,&review))
        return 87;
    struct timespec clockValue={0};
    if(clock_gettime(CLOCK_REALTIME,&clockValue)!=0 ||
       clockValue.tv_sec<0)return 87;
    const int64_t now=(int64_t)clockValue.tv_sec*1000+
                      clockValue.tv_nsec/1000000;
    if(now<review.issuedAt||now>=review.expiresAt)return 87;

    OSStatus found=errSecSuccess;
    SecKeyRef privateKey=findPrivateKey(&found);
    if(!privateKey)return 87;
    if(!validRsa2048(privateKey)){CFRelease(privateKey);return 87;}
    const char domain[]="bbx-reviewed-controller-rsa-pss-v1\n";
    NSMutableData *message=[NSMutableData dataWithBytes:domain
                                                    length:sizeof(domain)-1];
    [message appendBytes:source length:used];
    CFErrorRef error=NULL;
    CFDataRef signature=SecKeyCreateSignature(privateKey,
        kSecKeyAlgorithmRSASignatureMessagePSSSHA256,
        (CFDataRef)message,&error);
    CFRelease(privateKey);
    if(error)CFRelease(error);
    if(!signature)return 87;
    const bool valid=CFDataGetLength(signature)==256;
    if(!valid){CFRelease(signature);return 87;}
    const unsigned char *sig=CFDataGetBytePtr(signature);
    char hex[513]={0};
    const char alphabet[]="0123456789abcdef";
    for(size_t i=0;i<256;i++){
        hex[2*i]=alphabet[sig[i]>>4];
        hex[2*i+1]=alphabet[sig[i]&15];
    }
    CFRelease(signature);
    if(fwrite(source,1,used,stdout)!=used)return 87;
    if(fprintf(stdout,"controllerSig=%s\n",hex)!=
       (int)(sizeof("controllerSig=")-1+512+1))return 87;
    if(fflush(stdout)!=0)return 87;
    return 0;
}
int main(int argc,const char *argv[]){
    @autoreleasepool {
        if(argc!=2)return 90;
        if(strcmp(argv[1],"provision")==0)return provision();
        if(strcmp(argv[1],"public")==0)return exportPublic();
        if(strcmp(argv[1],"sign")==0)return signFixedSyntheticReview();
        return 90;
    }
}
