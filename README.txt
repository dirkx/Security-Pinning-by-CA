Quick example of securing a connection to an SSL (https) endpoint.
----------------------------------------------------------------

But rather than lock down to the (annual expiring) certificate of 
the server - we lock the connection down to a root CA; and then
accept any certificte signed by this root CA.

To test:
--------

-   Build the application and/or run the 'Create Certs' target once.

The latter will create a root->intermediate->server chain. 

-   The ca.der and proxy.conf files should now appear.

ca.der will be hard-coded into your application; while the generated
proxy.conf is needed by your server.

Wire this into your local apache - see the instructions at the start 
of the proxy.conf file.

Restart apache.

You now have a server running on https://localhost:8443/. Your browser
should not trust this server - as it is unware of the ca.der file.

Run the app. Study the output for details.

Adding this to your own apps:
-----------------------------

Create a suitable CA chain for your server.

Take the PinnedHTTPSConnection - modify it to suit your needs; and then add
your CA.der to the resource building.

Notes
-----
-   You can in fact simply use a self-signed cert for your server without
    any chain ado. In this case - just add the server public cert to the
    the resource bundle of the app*.
    
    However this means that a compromise or an expiry means you have
    to re-compile and re-distribute your app. Using a CA (with a 10+ year
    livetime) means you can simply re-create and re-sign without
    doung so.
    
-   Rather than using your own CA - you could also hardcode just the
    CA of your upstream provider. If you trust them not to double-
    cross you - that is nearly as good.
    
-   You can in fact code/add multiple CA's. It is not a bad idea to do
    so - and keep a 'spare CA' on paper/offline ready in the wings.









Footnotes:

* You may need to convert it to DER format with:

    openssl x509 -in server.pem -out server.der -outform DER
    
  as unlike apache and stunnel - iOS/Cocoa expect DER.
 
 
 
 

Copyright (c) 2013 Dirk-Willem van Gulik <dirkx@webweaving.org>,
                       All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

  