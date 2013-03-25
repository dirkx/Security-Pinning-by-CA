//
//  AppDelegate.m
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

#import "AppDelegate.h"
#import "PinnedHTTPSConnection.h"
#import "PinnedAndClientAuthHTTPSConnection.h"

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    _info.stringValue = @"Ready";

};

-(IBAction)runTests:(id)sender {

    NSString * derCaPath = [[NSBundle mainBundle] pathForResource:@"ca" ofType:@"der"];
    NSString * identityPath = [[NSBundle mainBundle] pathForResource:@"client" ofType:@"p12"];
    NSString * password = @"123456";
    
    if (NO) {
        NSURL * url = [NSURL URLWithString:@"https://localhost:8443"];
        PinnedHTTPSConnection  * conn = [[PinnedHTTPSConnection alloc] initWithURL:url
                                                                        withRootCA:derCaPath
                                                               strictHostNameCheck:NO];
        assert(conn);
        NSData  * results = [conn fetchSync];
        assert([results length]);
    }
    
    if (NO) {
        NSURL * url = [NSURL URLWithString:@"https://127.0.0.1:8443"];
        PinnedHTTPSConnection  * conn = [[PinnedHTTPSConnection alloc] initWithURL:url
                                                                        withRootCA:derCaPath
                                                               strictHostNameCheck:NO];
        assert(conn);
        NSData  * results = [conn fetchSync];
        assert([results length]);
        
    }

    if (YES) {
        NSURL * url = [NSURL URLWithString:@"https://localhost:8444"];
        PinnedAndClientAuthHTTPSConnection * conn =  [[PinnedAndClientAuthHTTPSConnection alloc] initWithURL:url
                                                                                            withPKCS12Client:identityPath
                                                                                                withPassword:password
                                                                                                  withRootCA:derCaPath
                                                                                         strictHostNameCheck:YES];
        assert(conn);
        NSData  * results = [conn fetchSync];
        assert([results length]);
    }
 }
@end
