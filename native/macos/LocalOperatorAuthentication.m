/*
 * Agent Black Box v0.8 — disposable macOS LocalAuthentication diagnostic.
 *
 * This standalone helper is NOT an operator approval authority, not called
 * by the HTTP server / MCP gateway, and never accesses any user documents.
 * A successful OS prompt must NOT be interpreted as a signed transfer grant.
 *
 * All CLI choices are fixed. There is no caller-controlled prompt text,
 * filesystem path, token, digest, operator assertion or approval payload.
 */
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <dispatch/dispatch.h>
#include <stdio.h>
#include <string.h>

static int fail(const char *marker,int code) {
    fprintf(stdout,"%s\n",marker);
    fflush(stdout);
    return code;
}
int main(int argc,const char *argv[]) {
    @autoreleasepool {
        if(argc!=2 || (strcmp(argv[1],"probe")!=0 &&
           strcmp(argv[1],"approve")!=0 && strcmp(argv[1],"cancel")!=0))
            return fail("BBX_LOCAL_AUTH_BAD_ARGS",90);
        const BOOL probe=strcmp(argv[1],"probe")==0;
        const BOOL requireSuccess=strcmp(argv[1],"approve")==0;
        LAContext *context=[[LAContext alloc]init];
        // Request a fresh Touch ID interaction, never intentionally reuse a
        // cached biometric success from this synthetic test context.
        context.touchIDAuthenticationAllowableReuseDuration=0;
        NSError *preflightError=nil;
        if(![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication
                                 error:&preflightError]) {
            // Deliberately omit localized error/user/account details.
            return fail("BBX_LOCAL_AUTH_UNAVAILABLE",82);
        }
        if(probe)return fail("BBX_LOCAL_AUTH_AVAILABLE",0);

        NSString *reason=@"Agent Black Box synthetic bbx-test-auth.txt review; no file will be changed.";
        dispatch_semaphore_t completed=dispatch_semaphore_create(0);
        __block BOOL succeeded=NO;
        __block NSInteger errorCode=0;
        __block BOOL localAuthenticationError=NO;
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
                 localizedReason:reason
                           reply:^(BOOL success,NSError *error) {
            succeeded=success && error==nil;
            errorCode=error.code;
            localAuthenticationError=error &&
                [error.domain isEqualToString:LAErrorDomain];
            dispatch_semaphore_signal(completed);
        }];
        const long waitResult=dispatch_semaphore_wait(completed,
            dispatch_time(DISPATCH_TIME_NOW,75LL*NSEC_PER_SEC));
        if(waitResult!=0) {
            [context invalidate];
            return fail("BBX_LOCAL_AUTH_TIMED_OUT",84);
        }
        [context invalidate];
        if(succeeded) {
            if(requireSuccess)return fail("BBX_LOCAL_AUTH_SUCCEEDED",0);
            // In the explicit negative test, a successful OS evaluation
            // must NEVER be accepted as cancellation.
            return fail("BBX_LOCAL_AUTH_UNEXPECTED_SUCCESS",85);
        }
        if(localAuthenticationError && errorCode==LAErrorUserCancel) {
            if(!requireSuccess)return fail("BBX_LOCAL_AUTH_USER_CANCELLED",83);
            return fail("BBX_LOCAL_AUTH_CANCELLED_WHEN_SUCCESS_REQUIRED",86);
        }
        return fail("BBX_LOCAL_AUTH_DENIED_OR_UNAVAILABLE",87);
    }
}
