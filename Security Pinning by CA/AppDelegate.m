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

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    _info.stringValue = @"Ready";

};

-(IBAction)runTests:(id)sender {
    _info.stringValue = @"running";

    NSString * derCaPath = [[NSBundle mainBundle] pathForResource:@"ca" ofType:@"der"];
    
    for(int i =0; i < 3; i++) {
        NSURL * url1 = [NSURL URLWithString:@"https://localhost:8443"];
        NSData  * results1 = [PinnedHTTPSConnection dataWithURL:url1
                                                     withRootCA:derCaPath
                                            strictHostNameCheck:YES];
        _info.stringValue = [NSString stringWithFormat:@"Foreground test %00d - %ld bytes",
                             i+1, [results1 length]];
    };

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        NSURL * url2 = [NSURL URLWithString:@"https://127.0.0.1:8443"];
        for(int i =0; i < 3; i++) {
            NSData  * results2 = [PinnedHTTPSConnection dataWithURL:url2
                                                         withRootCA:derCaPath
                                                strictHostNameCheck:NO];
            _info.stringValue = [NSString stringWithFormat:@"Background test %00d - %ld bytes",
                                 i+1, [results2 length]];
        }
        _info.stringValue = @"Done";
    });
}
@end
