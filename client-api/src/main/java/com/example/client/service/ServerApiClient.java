package com.example.client.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.ResourceAccessException;

import java.util.Map;

/**
 * Service for communicating with the Server API
 * Handles HTTP communication and service discovery
 */
@Service
public class ServerApiClient {

    private static final Logger logger = LoggerFactory.getLogger(ServerApiClient.class);

    @Value("${server.api.url:http://server-api:8081}")
    private String serverApiUrl;

    @Value("${server.api.process.endpoint:/api/process}")
    private String processEndpoint;

    @Value("${server.api.health.endpoint:/api/health}")
    private String healthEndpoint;

    private final RestTemplate restTemplate;

    public ServerApiClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * Send encrypted message to server for processing
     * @param encryptedMessage The JWE encrypted message
     * @return Encrypted response from server
     * @throws RuntimeException if communication fails
     */
    public String sendEncryptedMessage(String encryptedMessage) {
        try {
            String url = serverApiUrl + processEndpoint;
            logger.info("Sending encrypted message to server: {}", url);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            Map<String, String> requestBody = Map.of("encryptedData", encryptedMessage);
            HttpEntity<Map<String, String>> request = new HttpEntity<>(requestBody, headers);

            ResponseEntity<Map> response = restTemplate.postForEntity(url, request, Map.class);

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                Map<String, Object> responseBody = response.getBody();
                String encryptedResponse = (String) responseBody.get("encryptedResponse");

                if (encryptedResponse == null) {
                    throw new RuntimeException("Server response missing encrypted data");
                }

                logger.info("Successfully received encrypted response from server");
                return encryptedResponse;
            } else {
                throw new RuntimeException("Server returned non-success status: " + response.getStatusCode());
            }

        } catch (ResourceAccessException e) {
            logger.error("Failed to connect to server API at {}: {}", serverApiUrl, e.getMessage());
            throw new RuntimeException("Server API unavailable: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("Error communicating with server API: {}", e.getMessage(), e);
            throw new RuntimeException("Server communication failed: " + e.getMessage(), e);
        }
    }

    /**
     * Check if the server API is ready and responsive
     * @return true if server is ready
     */
    public boolean isServerReady() {
        try {
            String url = serverApiUrl + healthEndpoint;
            logger.debug("Checking server health at: {}", url);

            ResponseEntity<Map> response = restTemplate.getForEntity(url, Map.class);

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                Map<String, Object> responseBody = response.getBody();
                String status = (String) responseBody.get("status");
                boolean isUp = "UP".equals(status);

                logger.debug("Server health check result: {}", status);
                return isUp;
            }

            return false;

        } catch (Exception e) {
            logger.debug("Server health check failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Get server's public key for encryption
     * @return Server's public key in PEM format
     */
    public String getServerPublicKey() {
        try {
            String url = serverApiUrl + "/api/public-key";
            logger.info("Retrieving server public key from: {}", url);

            ResponseEntity<Map> response = restTemplate.getForEntity(url, Map.class);

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                Map<String, Object> responseBody = response.getBody();
                String publicKey = (String) responseBody.get("publicKey");

                if (publicKey == null) {
                    throw new RuntimeException("Server response missing public key");
                }

                logger.info("Successfully retrieved server public key");
                return publicKey;
            } else {
                throw new RuntimeException("Failed to retrieve server public key: " + response.getStatusCode());
            }

        } catch (Exception e) {
            logger.error("Error retrieving server public key: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to get server public key: " + e.getMessage(), e);
        }
    }

    /**
     * Get the configured server API URL
     * @return Server API base URL
     */
    public String getServerApiUrl() {
        return serverApiUrl;
    }
}
