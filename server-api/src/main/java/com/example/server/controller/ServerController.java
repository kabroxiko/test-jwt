package com.example.server.controller;

import com.example.server.service.JWEService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * REST Controller for Server API
 * Handles JWE decryption and processing of client requests
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class ServerController {

    private static final Logger logger = LoggerFactory.getLogger(ServerController.class);

    // Constants for response keys
    private static final String ERROR_KEY = "error";
    private static final String STATUS_KEY = "status";
    private static final String SUCCESS_VALUE = "success";
    private static final String DETAILS_KEY = "details";

    @Autowired
    private JWEService jweService;

    /**
     * Process encrypted data from client
     * @param request Map containing the encrypted data
     * @return ResponseEntity with encrypted response
     */
    @PostMapping("/process")
    public ResponseEntity<?> processEncryptedData(@RequestBody Map<String, String> request) {
        try {
            String encryptedData = request.get("encryptedData");
            if (encryptedData == null || encryptedData.trim().isEmpty()) {
                logger.warn("Empty encrypted data received");
                return ResponseEntity.badRequest().body(Map.of(ERROR_KEY, "Encrypted data cannot be empty"));
            }

            logger.info("Processing encrypted data from client");

            // Decrypt the client's message
            String decryptedMessage = jweService.decryptFromClient(encryptedData);
            logger.info("Successfully decrypted client message");

            // Process the message (simulate business logic)
            String processedMessage = processBusinessLogic(decryptedMessage);

            // Encrypt the response for the client
            String encryptedResponse = jweService.encryptForClient(processedMessage);
            logger.info("Successfully encrypted response for client");

            return ResponseEntity.ok(Map.of(
                "encryptedResponse", encryptedResponse,
                "processedAt", LocalDateTime.now().toString(),
                STATUS_KEY, SUCCESS_VALUE
            ));

        } catch (Exception e) {
            logger.error("Error processing encrypted data: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                ERROR_KEY, "Failed to process encrypted data",
                DETAILS_KEY, e.getMessage()
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

            return ResponseEntity.ok(Map.of(
                STATUS_KEY, jweServiceReady ? "UP" : "DOWN",
                "jweService", jweServiceReady ? "UP" : "DOWN",
                "timestamp", System.currentTimeMillis(),
                "version", "1.0.0"
            ));

        } catch (Exception e) {
            logger.error("Health check failed: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                STATUS_KEY, "DOWN",
                ERROR_KEY, e.getMessage(),
                "timestamp", System.currentTimeMillis()
            ));
        }
    }

    /**
     * Get public key for client encryption (in development only)
     * @return ResponseEntity with the public key
     */
    @GetMapping("/public-key")
    public ResponseEntity<?> getPublicKey() {
        try {
            String publicKey = jweService.getPublicKeyAsString();
            return ResponseEntity.ok(Map.of(
                "publicKey", publicKey,
                "keyFormat", "PEM",
                "algorithm", "RSA-OAEP-256",
                "contentEncryption", "A256GCM",
                STATUS_KEY, SUCCESS_VALUE
            ));
        } catch (Exception e) {
            logger.error("Error retrieving public key: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                ERROR_KEY, "Failed to retrieve public key",
                DETAILS_KEY, e.getMessage()
            ));
        }
    }

    /**
     * Get server information
     * @return ResponseEntity with server info
     */
    @GetMapping("/info")
    public ResponseEntity<?> getServerInfo() {
        return ResponseEntity.ok(Map.of(
            "serviceName", "server-api",
            "version", "1.0.0",
            "description", "JWE Server API for encrypted communication",
            "supportedAlgorithms", Map.of(
                "encryption", "RSA-OAEP-256",
                "contentEncryption", "A256GCM"
            ),
            "endpoints", Map.of(
                "process", "/api/process",
                "health", "/api/health",
                "publicKey", "/api/public-key",
                "info", "/api/info"
            ),
            STATUS_KEY, SUCCESS_VALUE
        ));
    }

    /**
     * Simulate business logic processing
     * @param message The decrypted message to process
     * @return Processed message
     */
    private String processBusinessLogic(String message) {
        // Simulate some business logic processing
        logger.debug("Processing business logic for message");

        String processed = String.format(
            "Server processed: '%s' at %s. Message length: %d characters. " +
            "Processing ID: %s",
            message,
            LocalDateTime.now(),
            message.length(),
            java.util.UUID.randomUUID().toString().substring(0, 8)
        );

        // Simulate processing time
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.warn("Business logic processing interrupted");
        }

        return processed;
    }
}
