package com.duracell.plugin.MtlsPlugin;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

public class MtlsPlugin extends CordovaPlugin {

    // ... utility methods to convert PEM to X509Certificate, etc. (Omitted for brevity) ...

    @Override
    public boolean execute(String action, JSONArray args, final CallbackContext callbackContext) throws JSONException {
        if ("provisionDevice".equals(action)) {
            final String ipAddress = args.getString(0);
            final int port = args.getInt(1);
            final String caCertPem = args.getString(2);
            final String clientCertPem = args.getString(3);
            final String clientKeyPem = args.getString(4); // Key must be loaded separately or from P12
            final byte[] protobufData = args.getString(5).getBytes(); // Simplified: actual data type handling needed

            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        // 1. Setup Trust Store (for CA Cert)
                        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
                        trustStore.load(null, null);
                        // Utility: Load X509Cert from PEM string (caCertPem)
                        X509Certificate caCert = loadCertificateFromPem(caCertPem);
                        trustStore.setCertificateEntry("ca_cert", caCert);
                        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                        tmf.init(trustStore);

                        // 2. Setup Key Store (for Client Cert and Key)
                        KeyStore keyStore = KeyStore.getInstance("PKCS12");
                        // NOTE: Typically, clientCertPem and clientKeyPem are merged into a PKCS#12 file
                        // The native code here must load the client key (private key) as well.
                        // Simplification: We assume key and cert are loaded into the keyStore
                        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                        keyStore.load(new ByteArrayInputStream(convertPemToP12(clientCertPem, clientKeyPem)), "password".toCharArray());
                        kmf.init(keyStore, "password".toCharArray()); // Use the P12 password

                        // 3. Create SSL Context and Socket
                        SSLContext sslContext = SSLContext.getInstance("TLS");
                        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
                        
                        Socket plainSocket = new Socket();
                        plainSocket.connect(new InetSocketAddress(ipAddress, port), 3000); // Connect Timeout

                        SSLSocket sslSocket = (SSLSocket) sslContext.getSocketFactory().createSocket(
                            plainSocket, ipAddress, port, true);
                        
                        sslSocket.setUseClientMode(false); // Server mode on the receiving end
                        sslSocket.startHandshake(); // Handshake performs mTLS

                        // 4. Data Exchange (Send Protobuf, Read ACK)
                        sslSocket.getOutputStream().write(protobufData);
                        sslSocket.getOutputStream().flush();

                        // Simplified: Read the ACK (assuming the ACK is small, 10 bytes max)
                        byte[] ackBuf = new byte[10];
                        int bytesRead = sslSocket.getInputStream().read(ackBuf);
                        
                        // 5. Close
                        sslSocket.close();

                        // 6. Success
                        callbackContext.success(true); 

                    } catch (Exception e) {
                        e.printStackTrace();
                        callbackContext.error("mTLS Provisioning Failed: " + e.getMessage());
                    }
                }
            });
            return true;
        }
        return false;
    }
    
    // Placeholder for utility function (Requires BouncyCastle/similar)
    private X509Certificate loadCertificateFromPem(String pem) throws Exception {
        // Implementation to parse PEM string to X509Certificate
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(pem.getBytes()));
    }
    
    // Placeholder for utility function
    private InputStream convertPemToP12(String certPem, String keyPem) {
        // Complex conversion required, typically involving BouncyCastle or pre-conversion.
        return null; // Must return a valid PKCS12 InputStream
    }
}