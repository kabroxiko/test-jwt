package com.example.client.controller;

import com.example.client.service.JWEService;
import com.example.client.service.ServerApiClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * REST Controller for Client API
 * Handles encryption and decryption operations for communication with Server API
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class ClientController {

    private static final Logger logger = LoggerFactory.getLogger(ClientController.class);

    @Autowired
    private JWEService jweService;

    @Autowired
    private ServerApiClient serverApiClient;

    /**
     * Encrypt a message and send it to the server
     * @param request Map containing the message to encrypt
     * @return ResponseEntity with the server's encrypted response
     */
    @PostMapping("/encrypt/message")
    public ResponseEntity<?> encryptAndSendMessage(@RequestBody Map<String, String> request) {
        try {
            String message = request.get("message");
            if (message == null || message.trim().isEmpty()) {
                logger.warn("Empty message received for encryption");
                return ResponseEntity.badRequest().body(Map.of("error", "Message cannot be empty"));
            }

            logger.info("Encrypting message for server transmission");

            // Encrypt the message with server's public key
            String encryptedMessage = jweService.encryptForServer(message);

            // Send encrypted message to server and get encrypted response
            String encryptedResponse = serverApiClient.sendEncryptedMessage(encryptedMessage);

            // Decrypt the server's response
            String decryptedResponse = jweService.decryptFromServer(encryptedResponse);

            logger.info("Successfully processed encrypted communication with server");

            return ResponseEntity.ok(Map.of(
                "originalMessage", message,
                "encryptedMessage", encryptedMessage,
                "serverResponse", decryptedResponse,
                "status", "success"
            ));

        } catch (Exception e) {
            logger.error("Error processing encrypted message: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "error", "Failed to process encrypted message",
                "details", e.getMessage()
            ));
        }
    }

    /**
     * Decrypt data that was previously encrypted
     * @param encryptedData The encrypted data to decrypt
     * @return ResponseEntity with the decrypted message
     */
    @GetMapping("/decrypt/{encryptedData}")
    public ResponseEntity<?> decryptMessage(@PathVariable String encryptedData) {
        try {
            logger.info("Attempting to decrypt provided data");

            String decryptedMessage = jweService.decryptFromServer(encryptedData);

            logger.info("Successfully decrypted message");

            return ResponseEntity.ok(Map.of(
                "encryptedData", encryptedData,
                "decryptedMessage", decryptedMessage,
                "status", "success"
            ));

        } catch (Exception e) {
            logger.error("Error decrypting message: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Failed to decrypt message",
                "details", e.getMessage()
            ));
        }
    }

    /**
     * Health check endpoint
     * @return ResponseEntity with service status
     */
    @GetMapping("/health")
    public ResponseEntity<?> health() {
        try {
            boolean jweServiceReady = jweService.isReady();
            boolean serverApiReady = serverApiClient.isServerReady();

            return ResponseEntity.ok(Map.of(
                "status", "UP",
                "jweService", jweServiceReady ? "UP" : "DOWN",
                "serverApi", serverApiReady ? "UP" : "DOWN",
                "timestamp", System.currentTimeMillis()
            ));

        } catch (Exception e) {
            logger.error("Health check failed: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "status", "DOWN",
                "error", e.getMessage(),
                "timestamp", System.currentTimeMillis()
            ));
        }
    }

    /**
     * Get public key for debugging purposes (in development only)
     * @return ResponseEntity with the public key
     */
    @GetMapping("/public-key")
    public ResponseEntity<?> getPublicKey() {
        try {
            String publicKey = jweService.getPublicKeyAsString();
            return ResponseEntity.ok(Map.of(
                "publicKey", publicKey,
                "keyFormat", "PEM",
                "status", "success"
            ));
        } catch (Exception e) {
            logger.error("Error retrieving public key: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "error", "Failed to retrieve public key",
                "details", e.getMessage()
            ));
        }
    }
}
