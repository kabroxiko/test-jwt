package com.example.server.service;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
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
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;

import jakarta.annotation.PostConstruct;

/**
 * JWE Service for Server API
 * Handles encryption and decryption operations using RSA-OAEP and A256GCM
 */
@Service
public class JWEService {

    private static final Logger logger = LoggerFactory.getLogger(JWEService.class);

    private static final String KEY_ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;

    @Value("${jwe.server.private-key:}")
    private String serverPrivateKeyPem;

    @Value("${jwe.server.public-key:}")
    private String serverPublicKeyPem;

    @Value("${jwe.client.public-key:}")
    private String clientPublicKeyPem;

    private RSAPrivateKey serverPrivateKey;
    private RSAPublicKey serverPublicKey;
    private RSAPublicKey clientPublicKey;

    private volatile boolean ready = false;

    @PostConstruct
    public void init() {
        try {
            logger.info("Initializing JWE Service for Server API");

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
            throw new IllegalStateException("JWE Service initialization failed", e);
        }
    }

    private boolean hasValidKeys() {
        return serverPrivateKeyPem != null && !serverPrivateKeyPem.trim().isEmpty() &&
               serverPublicKeyPem != null && !serverPublicKeyPem.trim().isEmpty();
    }

    private void loadKeysFromConfig() throws GeneralSecurityException {
        logger.info("Loading RSA keys from configuration");

        // Load server keys
        serverPrivateKey = loadPrivateKeyFromPem(serverPrivateKeyPem);
        serverPublicKey = loadPublicKeyFromPem(serverPublicKeyPem);

        // Load client public key if available
        if (clientPublicKeyPem != null && !clientPublicKeyPem.trim().isEmpty()) {
            clientPublicKey = loadPublicKeyFromPem(clientPublicKeyPem);
        }

        logger.info("Successfully loaded RSA keys from configuration");
    }

    private void generateAndStoreKeys() throws NoSuchAlgorithmException {
        logger.info("Generating new RSA key pair for server");

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyGenerator.initialize(KEY_SIZE);
        KeyPair keyPair = keyGenerator.generateKeyPair();

        serverPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        serverPublicKey = (RSAPublicKey) keyPair.getPublic();

        logger.info("Successfully generated new RSA key pair (size: {} bits)", KEY_SIZE);
    }

    /**
     * Decrypt a message from the client using server's private key
     * @param encryptedMessage The JWE encrypted message
     * @return Decrypted message
     * @throws JOSEException if decryption fails
     */
    public String decryptFromClient(String encryptedMessage) throws JOSEException, java.text.ParseException {
        logger.debug("Decrypting message from client");

        // Parse JWE object
        JWEObject jweObject = JWEObject.parse(encryptedMessage);

        // Decrypt with server's private key
        jweObject.decrypt(new RSADecrypter(serverPrivateKey));

        String decrypted = jweObject.getPayload().toString();
        logger.debug("Successfully decrypted message from client");

        return decrypted;
    }

    /**
     * Encrypt a message for the client using client's public key
     * @param message The message to encrypt
     * @return JWE encrypted string
     * @throws JOSEException if encryption fails
     */
    public String encryptForClient(String message) throws JOSEException {
        if (clientPublicKey == null) {
            throw new IllegalStateException("Client public key not available for encryption");
        }

        logger.debug("Encrypting message for client transmission");

        // Create JWE header
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .contentType("text/plain")
                .build();

        // Create JWE object
        JWEObject jweObject = new JWEObject(header, new Payload(message));

        // Encrypt with client's public key
        jweObject.encrypt(new RSAEncrypter(clientPublicKey));

        String encrypted = jweObject.serialize();
        logger.debug("Successfully encrypted message for client");

        return encrypted;
    }

    /**
     * Get server's public key as PEM string
     * @return Public key in PEM format
     */
    public String getPublicKeyAsString() {
        if (serverPublicKey == null) {
            throw new IllegalStateException("Server public key not available");
        }

        byte[] encoded = serverPublicKey.getEncoded();
        String base64 = Base64.getEncoder().encodeToString(encoded);

        return "-----BEGIN PUBLIC KEY-----\n" +
               base64.replaceAll("(.{64})", "$1\n") +
               "\n-----END PUBLIC KEY-----";
    }

    /**
     * Set client's public key for encryption
     * @param clientPublicKeyPem Client's public key in PEM format
     */
    public void setClientPublicKey(String clientPublicKeyPem) {
        try {
            this.clientPublicKey = loadPublicKeyFromPem(clientPublicKeyPem);
            logger.info("Client public key updated successfully");
        } catch (GeneralSecurityException e) {
            logger.error("Failed to set client public key: {}", e.getMessage(), e);
            throw new IllegalArgumentException("Failed to set client public key", e);
        }
    }

    /**
     * Check if the JWE service is ready for use
     * @return true if service is ready
     */
    public boolean isReady() {
        return ready && serverPrivateKey != null && serverPublicKey != null;
    }

    private RSAPrivateKey loadPrivateKeyFromPem(String pemKey) throws GeneralSecurityException {
        String privateKeyPEM = pemKey
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

        return (RSAPrivateKey) keyFactory.generatePrivate(spec);
    }

    private RSAPublicKey loadPublicKeyFromPem(String pemKey) throws GeneralSecurityException {
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
