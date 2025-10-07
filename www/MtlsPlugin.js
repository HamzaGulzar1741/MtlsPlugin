// MtlsPlugin.js
var exec = require('cordova/exec');

/**
 * Initiates the mTLS connection, sends Protobuf data, and waits for an ACK.
 * @param {string} ipAddress - IP address of the provisioning server.
 * @param {number} port - Port of the provisioning server (58585).
 * @param {string} caCertPem - PEM content of the CA certificate.
 * @param {string} clientCertPem - PEM content of the client certificate.
 * @param {string} clientKeyPem - PEM content of the client private key.
 * @param {ArrayBuffer} protobufData - Protobuf data (binary) to send.
 * @param {function} success - Success callback (receives true on successful provisioning).
 * @param {function} error - Error callback (receives an error message).
 */
exports.provisionDevice = function (ipAddress, port, caCertPem, clientCertPem, clientKeyPem, protobufData, success, error) {
    // Note: Protobuf data needs to be converted to a string representation 
    // that can be passed through the bridge (e.g., Base64 or a byte array string).
    // For simplicity here, we assume it's passed efficiently.
    exec(
        success,
        error,
        'MtlsPlugin', // The service name
        'provisionDevice', // The native action name
        [ipAddress, port, caCertPem, clientCertPem, clientKeyPem, protobufData]
    );
};