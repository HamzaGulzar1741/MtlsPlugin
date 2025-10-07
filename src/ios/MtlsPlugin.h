// MtlsPlugin.h
#import <Cordova/CDVPlugin.h>

/**
 * @brief Cordova plugin for Mutual TLS (mTLS) connectivity.
 *
 * This class implements the native iOS logic for opening a secure TCP 
 * socket connection, performing the mTLS handshake using a client certificate
 * and a CA certificate, sending Protobuf data, and receiving an ACK.
 */
@interface MtlsPlugin : CDVPlugin <NSStreamDelegate> // NSStreamDelegate is often used for non-blocking I/O

/**
 * @brief Initiates the mTLS connection and provisioning process.
 * * This method is called from the JavaScript bridge via cordova.exec.
 *
 * @param command The command object containing arguments from JavaScript.
 * Arguments are expected to be: 
 * 0: ipAddress (NSString*)
 * 1: port (NSNumber*)
 * 2: caCertPem (NSString*)
 * 3: clientCertPem (NSString*)
 * 4: clientKeyPem (NSString*)
 * 5: protobufData (NSData*)
 */
- (void)provisionDevice:(CDVInvokedUrlCommand*)command;

@end