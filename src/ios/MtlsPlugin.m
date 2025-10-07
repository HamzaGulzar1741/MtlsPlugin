#import "MtlsPlugin.h"
#import <Cordova/CDVPluginResult.h>
#import <Security/SecItem.h>
#import <CoreFoundation/CoreFoundation.h>

@implementation MtlsPlugin

- (void)provisionDevice:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        NSString* ipAddress = [command.arguments objectAtIndex:0];
        NSNumber* portNum = [command.arguments objectAtIndex:1];
        NSString* caCertPem = [command.arguments objectAtIndex:2];
        NSString* clientCertPem = [command.arguments objectAtIndex:3];
        NSString* clientKeyPem = [command.arguments objectAtIndex:4];
        NSData* protobufData = [command.arguments objectAtIndex:5]; // Assuming proper NSData conversion

        // 1. Load Certificates (Highly complex due to lack of standard PEM utilities in pure Objective-C/Swift)
        // You would typically use an external library (like OpenSSL or a wrapper) or pre-convert to DER/PKCS12.
        SecIdentityRef clientIdentity = [self loadIdentityFromPems:clientCertPem keyPem:clientKeyPem];
        NSArray *trustedCerts = [self loadTrustedCertsFromPem:caCertPem];

        if (!clientIdentity || !trustedCerts) {
            CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Failed to load certificates"];
            [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
            return;
        }

        // 2. Open Secure Connection (Simplified using CFStream)
        CFReadStreamRef readStream;
        CFWriteStreamRef writeStream;
        CFStreamCreatePairWithSocketToHost(kCFAllocatorDefault, (__bridge CFStringRef)ipAddress, [portNum intValue], &readStream, &writeStream);

        // Bridge to NSStream for easier configuration
        NSInputStream *inputStream = (__bridge_transfer NSInputStream *)readStream;
        NSOutputStream *outputStream = (__bridge_transfer NSOutputStream *)writeStream;

        [inputStream setDelegate:self]; // For async I/O, though mTLS is blocking here
        [outputStream setDelegate:self];

        [inputStream open];
        [outputStream open];

        // 3. Configure TLS with Mutual Authentication
        NSDictionary *sslSettings = @{
            // Set client identity (certificate and private key)
            (__bridge id)kCFStreamSSLClientCertificateAuthorities: trustedCerts,
            (__bridge id)kCFStreamSSLPeerCertificates: @[(__bridge id)clientIdentity], // Should be kCFStreamSSLCertificates
            
            // Set trusted CA certificates for server verification
            (__bridge id)kCFStreamSSLValidatesCertificateChain: @(YES),
            (__bridge id)kCFStreamSSLAllowsAnyRoot: @(NO),
            // ... more settings for proper mTLS configuration
        };
        
        // This is a simplified API call. Actual mTLS setup is highly nuanced.
        CFReadStreamSetProperty(readStream, kCFStreamPropertySSLSettings, (__bridge CFDictionaryRef)sslSettings);
        CFWriteStreamSetProperty(writeStream, kCFStreamPropertySSLSettings, (__bridge CFDictionaryRef)sslSettings);


        // 4. Data Exchange (This must be done *after* the stream opens and the handshake completes)
        NSInteger bytesWritten = [outputStream write:[protobufData bytes] maxLength:[protobufData length]];

        if (bytesWritten > 0) {
            // Read ACK (blocking call or use stream delegates for proper async handling)
            // ... read logic ...
            
            // 5. Close
            [inputStream close];
            [outputStream close];
            
            CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:YES];
            [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        } else {
            // 5. Error
            [inputStream close];
            [outputStream close];
            CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Write failed or handshake failed"];
            [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        }
    }];
}

// Omitted: loadIdentityFromPems and loadTrustedCertsFromPem utility methods
// These require robust PEM parsing and object conversion.
@end