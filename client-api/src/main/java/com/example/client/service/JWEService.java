package com.example.client.service;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;

import jakarta.annotation.PostConstruct;

/**
 * JWE Service for Client API
 * Handles encryption and decryption operations using RSA-OAEP and A256GCM
 */
@Service
public class JWEService {

    private static final Logger logger = LoggerFactory.getLogger(JWEService.class);

    // Constants for response keys
    public static final String ERROR_KEY = "error";
    public static final String STATUS_KEY = "status";
    public static final String SUCCESS_VALUE = "success";
    public static final String DETAILS_KEY = "details";

    private static final String KEY_ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;

    @Value("${jwe.client.private-key:}")
    private String clientPrivateKeyPem;

    @Value("${jwe.client.public-key:}")
    private String clientPublicKeyPem;

    @Value("${jwe.server.public-key:}")
    private String serverPublicKeyPem;

    private RSAPrivateKey clientPrivateKey;
    private RSAPublicKey clientPublicKey;
    private RSAPublicKey serverPublicKey;

    private volatile boolean ready = false;

    @PostConstruct
    public void init() {
        try {
            logger.info("Initializing JWE Service for Client API");

            if (hasValidKeys()) {
                loadKeysFromConfig();
            } else {
                generateAndStoreKeys();
            }

            ready = true;
            logger.info("JWE Service successfully initialized");

        } catch (Exception e) {
            logger.error("Failed to initialize JWE Service: {}", e.getMessage(), e);
            ready = false;
            throw new RuntimeException("JWE Service initialization failed", e);
        }
    }

    private boolean hasValidKeys() {
        return clientPrivateKeyPem != null && !clientPrivateKeyPem.trim().isEmpty() &&
               clientPublicKeyPem != null && !clientPublicKeyPem.trim().isEmpty();
    }

    private void loadKeysFromConfig() throws Exception {
        logger.info("Loading RSA keys from configuration");

        // Load client keys
        clientPrivateKey = loadPrivateKeyFromPem(clientPrivateKeyPem);
        clientPublicKey = loadPublicKeyFromPem(clientPublicKeyPem);

        // Load server public key if available
        if (serverPublicKeyPem != null && !serverPublicKeyPem.trim().isEmpty()) {
            serverPublicKey = loadPublicKeyFromPem(serverPublicKeyPem);
        }

        logger.info("Successfully loaded RSA keys from configuration");
    }

    private void generateAndStoreKeys() throws Exception {
        logger.info("Generating new RSA key pair for client");

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyGenerator.initialize(KEY_SIZE);
        KeyPair keyPair = keyGenerator.generateKeyPair();

        clientPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        clientPublicKey = (RSAPublicKey) keyPair.getPublic();

        logger.info("Successfully generated new RSA key pair (size: {} bits)", KEY_SIZE);
    }

    /**
     * Encrypt a message for the server using server's public key
     * @param message The message to encrypt
     * @return JWE encrypted string
     * @throws Exception if encryption fails
     */
    public String encryptForServer(String message) throws Exception {
        if (serverPublicKey == null) {
            throw new IllegalStateException("Server public key not available for encryption");
        }

        logger.debug("Encrypting message for server transmission");

        // Create JWE header
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .contentType("text/plain")
                .build();

        // Create JWE object
        JWEObject jweObject = new JWEObject(header, new Payload(message));

        // Encrypt with server's public key
        jweObject.encrypt(new RSAEncrypter(serverPublicKey));

        String encrypted = jweObject.serialize();
        logger.debug("Successfully encrypted message for server");

        return encrypted;
    }

    /**
     * Decrypt a message from the server using client's private key
     * @param encryptedMessage The JWE encrypted message
     * @return Decrypted message
     * @throws Exception if decryption fails
     */
    public String decryptFromServer(String encryptedMessage) throws Exception {
        logger.debug("Decrypting message from server");

        // Parse JWE object
        JWEObject jweObject = JWEObject.parse(encryptedMessage);

        // Decrypt with client's private key
        jweObject.decrypt(new RSADecrypter(clientPrivateKey));

        String decrypted = jweObject.getPayload().toString();
        logger.debug("Successfully decrypted message from server");

        return decrypted;
    }

    /**
     * Get client's public key as PEM string
     * @return Public key in PEM format
     */
    public String getPublicKeyAsString() {
        if (clientPublicKey == null) {
            throw new IllegalStateException("Client public key not available");
        }

        byte[] encoded = clientPublicKey.getEncoded();
        String base64 = Base64.getEncoder().encodeToString(encoded);

        return "-----BEGIN PUBLIC KEY-----\n" +
               base64.replaceAll("(.{64})", "$1\n") +
               "\n-----END PUBLIC KEY-----";
    }

    /**
     * Set server's public key for encryption
     * @param serverPublicKeyPem Server's public key in PEM format
     */
    public void setServerPublicKey(String serverPublicKeyPem) {
        try {
            this.serverPublicKey = loadPublicKeyFromPem(serverPublicKeyPem);
            logger.info("Server public key updated successfully");
        } catch (Exception e) {
            logger.error("Failed to set server public key: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to set server public key", e);
        }
    }

    /**
     * Check if the JWE service is ready for use
     * @return true if service is ready
     */
    public boolean isReady() {
        return ready && clientPrivateKey != null && clientPublicKey != null;
    }

    private RSAPrivateKey loadPrivateKeyFromPem(String pemKey) throws Exception {
        String privateKeyPEM = pemKey
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

        return (RSAPrivateKey) keyFactory.generatePrivate(spec);
    }

    private RSAPublicKey loadPublicKeyFromPem(String pemKey) throws Exception {
        String publicKeyPEM = pemKey
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

        return (RSAPublicKey) keyFactory.generatePublic(spec);
    }
}
