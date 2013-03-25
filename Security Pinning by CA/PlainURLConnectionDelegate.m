//
//  PlainURLConnectionDelegate.m
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

#import "PlainURLConnectionDelegate.h"

@implementation PlainURLConnectionDelegate {
    NSURL * url;
    NSMutableData * receivedData;
    dispatch_semaphore_t semaphore;
}

- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response
{
    [receivedData setLength:0];
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
{
    if (!receivedData) {
        receivedData = [[NSMutableData alloc] init];
    }
    [receivedData appendData:data];
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection {
    dispatch_semaphore_signal(semaphore);
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error {
    receivedData = nil;
    dispatch_semaphore_signal(semaphore);
}

- (NSCachedURLResponse *)connection:(NSURLConnection *)connection willCacheResponse:(NSCachedURLResponse *)cachedResponse {
    return nil;
}

- (NSURLRequest *)connection:(NSURLConnection *)connection willSendRequest:(NSURLRequest *)request redirectResponse:(NSURLResponse *)redirectResponse {
    return request;
}

-(void)dealloc {
    receivedData = nil;
}

-(id)initWithURL:(NSURL *)anUrl {
    if (self = [super init]) {
        url = anUrl;
    }
    return self;
}

-(NSData *)fetchSync {
    
    NSURLRequest * request = [NSURLRequest requestWithURL:url];
    if (!request)
        return nil;
    
    NSURLConnection * connection = [[NSURLConnection alloc] initWithRequest:request
                                                                   delegate:self];
    if (!connection)
        return nil;
    
    semaphore = dispatch_semaphore_create(1);
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    
    [connection start];
    
    // We cannot camp on the semaphore with a DISPATCH_TIME_FOREVER
    // as NSURLConnection will execute on this thread.
    //
    while(dispatch_semaphore_wait(semaphore, 0) != 0) {
        // [[NSRunLoop currentRunLoop] runUntilDate:[NSDate distantFuture]];
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }
    dispatch_semaphore_signal(semaphore);
    
    return receivedData;
}


@end
