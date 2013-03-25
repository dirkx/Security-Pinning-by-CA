//
//  PinnedAndClientAuthHTTPSConnection.m
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

#import "PinnedAndClientAuthHTTPSConnection.h"

#if TARGET_API_MAC_OSX
#include <openssl/x509.h>
#endif

@implementation PinnedAndClientAuthHTTPSConnection {
    SecIdentityRef identityRef;
    CFArrayRef identityChain;
}

- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace {
    
    if ([protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodClientCertificate]) {
#if DEBUG
        NSLog(@"We're asked if we can do client auth - and it is indicated that the server accepts client certs from:");
        for(NSData * dnDERs in protectionSpace.distinguishedNames) {
#if TARGET_API_MAC_OSX
            const unsigned char * ptr = [dnDERs bytes];
            X509_NAME * dn = d2i_X509_NAME(NULL, &ptr, [dnDERs length]);
            if (dn) {
                char buff[1024];
                if (X509_NAME_oneline(dn, buff,sizeof(buff)) != NULL)
                    NSLog(@" - DN: %s", buff);
                else
                    NSLog(@" - Unprintable DN; DER is : %@", dnDERs);
            } else {
                NSLog(@" - Unparsable DN; DER: %@", dnDERs);
            }
#else
            NSLog(@" - DER: %@", dnDERs);
#endif
        }
#endif
        // We're not fussy - and actually ignore the above list somewhat - and simply
        // say yes. When it comes to authentication (in didReceiveAuthenticationChallenge)
        // we then simply throw it what we have. Not perhaps best practice - but it
        // will do for this demo.
        //
        return YES;
    }
    return [super connection:connection canAuthenticateAgainstProtectionSpace:protectionSpace];
}

- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    OSStatus err;
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodClientCertificate]) {
        // We simply throw the server what we have - and will leave it at that.
        //
        NSURLCredential *credential = [NSURLCredential credentialWithIdentity:identityRef
                                                                 certificates:(__bridge NSArray *)identityChain
                                                                  persistence:NSURLCredentialPersistenceForSession];
        if (!credential) {
            NSLog(@"Failed to create an identity with the provided credentials. Canceling.");
            [[challenge sender] cancelAuthenticationChallenge:challenge];
            return;
        }

        if (!identityRef) {
            NSLog(@"No client certs to identify with. giving up.");
            [[challenge sender] cancelAuthenticationChallenge:challenge];
            return;            
        }
#if DEBUG
        SecCertificateRef certRef = NULL;
        if ((err=SecIdentityCopyCertificate( identityRef, &certRef)) != noErr) {
            CFStringRef str =SecCopyErrorMessageString(err,NULL);
            NSLog(@"%s: Could not SecIdentityCopyCertificate: %@", __PRETTY_FUNCTION__, str);
        }
        
        CFStringRef str = SecCertificateCopyLongDescription(kCFAllocatorDefault, certRef, nil);
        NSLog(@"We're identifying to the server with the cert '%@' - and hope for the best.", str);
        if (str)
            CFRelease(str);
        if (certRef)
            CFRelease(certRef);
#endif

        [challenge.sender useCredential:credential forAuthenticationChallenge:challenge];
        return;
    }

    [super connection:connection didReceiveAuthenticationChallenge:challenge];
}

-(id)initWithURL:(NSURL *)anUrl withPKCS12Client:(NSString *)pkcs12Path withPassword:(NSString *)password withRootCA:(NSString *)caDerFilePath strictHostNameCheck:(BOOL)check {
    
    self = [super initWithURL:anUrl withRootCA:caDerFilePath strictHostNameCheck:check];
    
    if (!self)
        return nil;
            
    if (!pkcs12Path) {
        NSLog(@"%s: No path for the pkcs#12 file", __PRETTY_FUNCTION__);
        return nil;
    };
    
    NSData * pkcs12data = [NSData dataWithContentsOfFile:pkcs12Path];
    if (!pkcs12data) {
        NSLog(@"%s: Could not read pkcs#12 file <%@>", __PRETTY_FUNCTION__, pkcs12Path);
        return nil;
    }
    const void *keys[] =   { kSecImportExportPassphrase };
    const void *values[] = { (__bridge const void *)(password) };
    CFDictionaryRef optionsDictionary = NULL;

    optionsDictionary = CFDictionaryCreate(
                                           NULL, keys,
                                           values, (password ? 1 : 0),
                                           NULL, NULL);
    
    CFArrayRef results;
    
    OSStatus err = SecPKCS12Import((__bridge CFDataRef)(pkcs12data), optionsDictionary, &results);
    if (err != noErr) {
        CFStringRef str =SecCopyErrorMessageString(err,NULL);
        NSLog(@"%s: Could not import pkcs#12 file <%@>: %@", __PRETTY_FUNCTION__, pkcs12Path, str);
        return nil;
        CFRelease(str);
    }
    
    if (CFArrayGetCount(results) < 1) {
        NSLog(@"%s: Nothing usable in the pkcs#12 file <%@>", __PRETTY_FUNCTION__, pkcs12Path);
        return nil;
    }
    
    if (CFArrayGetCount(results) > 1) {
        NSLog(@"%s: Too many entreis in the the pkcs#12 file, not smart enough. <%@>", __PRETTY_FUNCTION__, pkcs12Path);
        return nil;
    }

    CFDictionaryRef result = CFArrayGetValueAtIndex(results, 0);

    identityRef = (SecIdentityRef)CFDictionaryGetValue(result, kSecImportItemIdentity);
    CFRetain(identityRef);
    identityChain = (CFArrayRef)CFDictionaryGetValue(result, kSecImportItemCertChain);
    
    if (!identityRef) {
        NSLog(@"%s: No identity in the pkcs#12 file <%@>", __PRETTY_FUNCTION__, pkcs12Path);
        return nil;
    }
    

    return self;
}

-(id)initWithURL:(NSURL *)anUrl withIdentity:(SecIdentityRef)anIdentityRef withIdentityChain:(NSArray*)aClientChainOfSecCertificateRef withRootCAs:(NSArray *)anArrayOfSecCertificateRef strictHostNameCheck:(BOOL)check {
    self = [super initWithURL:anUrl withRootCAs:anArrayOfSecCertificateRef strictHostNameCheck:check];
    
    if (!self)
        return nil;
        
    identityRef = anIdentityRef;
    CFRetain(identityRef);
    
    identityChain = CFArrayCreateMutableCopy(kCFAllocatorDefault, [aClientChainOfSecCertificateRef count] + 1, CFBridgingRetain(aClientChainOfSecCertificateRef));
    CFArrayInsertValueAtIndex((CFMutableArrayRef)identityChain, 0, identityRef);
    
    return self;
}

-(void)dealloc {
    if (identityChain)
        CFRelease(identityChain);

    if (identityRef)
        CFRelease(identityRef);
}
@end
