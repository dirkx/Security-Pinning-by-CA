//
//  PinnedHTTPSConnection.m
//  Security Pinning by CA
//
// Copyright (c) 2013 Dirk-Willem van Gulik <dirkx@webweaving.org>,
//                       All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#import "PinnedHTTPSConnection.h"

@implementation PinnedHTTPSConnection {
    CFArrayRef caChainArrayRef;
    BOOL checkHostname;
}

- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace {

    return [protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust];
}

- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {

    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        SecTrustRef trust = nil;
        SecTrustResultType result;
        OSStatus err = errSecSuccess;

#if DEBUG
        {
            NSLog(@"Chain received from the server (working 'up'):");
            CFIndex certificateCount = SecTrustGetCertificateCount(challenge.protectionSpace.serverTrust);
            for(int i = 0; i < certificateCount; i++) {
                SecCertificateRef certRef = SecTrustGetCertificateAtIndex(challenge.protectionSpace.serverTrust, i);
                CFStringRef str = SecCertificateCopyLongDescription(kCFAllocatorDefault, certRef, nil);
                NSLog(@"   %02i: %@", 1+i, str);
                CFRelease(str);
            }
            
            NSLog(@"Local Roots we trust:");
            for(int i = 0; i < CFArrayGetCount(caChainArrayRef); i++) {
                SecCertificateRef certRef = (SecCertificateRef) CFArrayGetValueAtIndex(caChainArrayRef, i);
                CFStringRef str = SecCertificateCopyLongDescription(kCFAllocatorDefault, certRef, nil);
                NSLog(@"   %02i: %@", 1+i, str);
                CFRelease(str);
            }
        }
#endif
    
        if (checkHostname) {
            // We use the standard Policy of SSL - which also checks hostnames.
            // -- see SecPolicyCreateSSL() for details.
            //
            trust = challenge.protectionSpace.serverTrust;
            //
#if DEBUG
            NSLog(@"The certificate is expected to match '%@' as the hostname",
                  challenge.protectionSpace.host);
#endif
        } else {
            // Create a new Policy - which goes easy on the hostname.
            //
            
            // Extract the chain of certificates provided by the server.
            //
            CFIndex certificateCount = SecTrustGetCertificateCount(challenge.protectionSpace.serverTrust);
            NSMutableArray * chain = [NSMutableArray array];
            
            for(int i = 0; i < certificateCount; i++) {
                SecCertificateRef certRef = SecTrustGetCertificateAtIndex(challenge.protectionSpace.serverTrust, i);
                [chain addObject:(__bridge id)(certRef)];
            }

            // And create a bland policy which only checks signature paths.
            //
            if (err == errSecSuccess)
                err = SecTrustCreateWithCertificates((__bridge CFArrayRef)(chain),
                                                     SecPolicyCreateBasicX509(), &trust);
#if DEBUG
            NSLog(@"The certificate is NOT expected to match the hostname '%@' ",
                  challenge.protectionSpace.host);
#endif
        };

        // Explicity specify the list of certificates we actually trust (i.e. those I have hardcoded
        // in the app - rather than those provided by some randon server on the internet).
        //
        if (err == errSecSuccess)
            err = SecTrustSetAnchorCertificates(trust,caChainArrayRef);

        // And only use above - i.e. do not check the system its global keychain or something
        // else the user may have fiddled with.
        //
        if (err == errSecSuccess)
            err = SecTrustSetAnchorCertificatesOnly(trust, YES);

        if (err == errSecSuccess)
            err = SecTrustEvaluate(trust, &result);
        
        
        if (err == errSecSuccess) {
            switch (result) {
                case kSecTrustResultProceed:
                    // User gave explicit permission to trust this specific
                    // root at some point (in the past).
                    //
                    NSLog(@"GOOD. kSecTrustResultProceed - the user explicitly trusts this CA");
                    [challenge.sender useCredential:[NSURLCredential credentialForTrust:trust]
                         forAuthenticationChallenge:challenge];
                    goto done;
                    break;
                case kSecTrustResultUnspecified:
                    // The chain is technically valid and matches up to the root
                    // we provided. The user has not had any say in this though,
                    // hence it is not a kSecTrustResultProceed.
                    //
                    NSLog(@"GOOD. kSecTrustResultUnspecified - So things are technically trusted. But the user was not involved.");
                    [challenge.sender useCredential:[NSURLCredential credentialForTrust:trust]
                         forAuthenticationChallenge:challenge];
                    goto done;
                    break;
                case kSecTrustResultInvalid:
                    NSLog(@"FAIL. kSecTrustResultInvalid");
                    break;
                case kSecTrustResultDeny:
                    NSLog(@"FAIL. kSecTrustResultDeny (i.e. user said no explicitly)");
                    break;
                case kSecTrustResultFatalTrustFailure:
                    NSLog(@"FAIL. kSecTrustResultFatalTrustFailure");
                    break;
                case kSecTrustResultOtherError:
                    NSLog(@"FAIL. kSecTrustResultOtherError");
                    break;
                case kSecTrustResultRecoverableTrustFailure:
                    NSLog(@"FAIL. kSecTrustResultRecoverableTrustFailure (i.e. user could say OK, but has not been asked this)");
                    break;
                default:
                    NSAssert(NO,@"Unexpected result: %d", result);
                    break;
            }
            // Reject.
            [challenge.sender cancelAuthenticationChallenge:challenge];
            goto done;
        };
        CFStringRef str =SecCopyErrorMessageString(err,NULL);
        NSLog(@"Internal failure to validate: result %@", str);
        CFRelease(str);
                  
        [[challenge sender] cancelAuthenticationChallenge:challenge];

    done:
        if (!checkHostname)
            CFRelease(trust);
        return;
    }
    // In this example we can cancel at this point - as we only do
    // canAuthenticateAgainstProtectionSpace against ServerTrust.
    //
    // But in other situations a more gentle continue may be appropriate.
    //
    // [challenge.sender continueWithoutCredentialForAuthenticationChallenge:challenge];

    NSLog(@"Not something we can handle - so we're canceling it.");
    [challenge.sender cancelAuthenticationChallenge:challenge];
}

-(id)initWithURL:(NSURL *)anUrl withRootCA:(NSString *)caDerFilePath strictHostNameCheck:(BOOL)check {
    
    NSData *derCA = [NSData dataWithContentsOfFile:caDerFilePath];
    if (!derCA) {
        return nil;
    }

    SecCertificateRef caRef = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)derCA);
    if (!caRef) {
        return nil;
    }
    NSArray * chain = [NSArray arrayWithObject:(__bridge id)(caRef)];
    
    return [self initWithURL:anUrl withRootCAs:chain strictHostNameCheck:check];
}

-(id)initWithURL:(NSURL *)anUrl withRootCAs:(NSArray *)anArrayOfSecCertificateRef strictHostNameCheck:(BOOL)check {

    self = [super initWithURL:anUrl];
    if (!self)
        return nil;
    
    checkHostname = check;
    caChainArrayRef = CFBridgingRetain(anArrayOfSecCertificateRef);

    return self;
}

-(void)dealloc {
    if (caChainArrayRef)
        CFRelease(caChainArrayRef);
}
@end
