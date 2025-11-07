# Spring Boot JWE Client-Server Demo on Kubernetes

A complete demonstration of Spring Boot applications using JSON Web Encryption (JWE) for end-to-end encryption, deployed on Kubernetes with proper security practices.

## 🎯 Overview

This project demonstrates:

- **End-to-End Encryption**: JWE (JSON Web Encryption) using RSA-OAEP-256 and A256GCM
- **Microservices Architecture**: Client API and Server API with secure communication
- **Kubernetes Deployment**: Production-ready manifests with ConfigMaps, Secrets, and Services
- **Security Best Practices**: Proper key management, non-root containers, and network policies

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐
│   Client API    │    │   Server API    │
│   (Port 8080)   │────│   (Port 8081)   │
│                 │    │                 │
│ • JWE Encryption│    │ • JWE Decryption│
│ • RESTful API   │    │ • Message Proc. │
│ • Health Checks │    │ • Health Checks │
└─────────────────┘    └─────────────────┘
         │                       │
         └───────────────────────┘
                 │
        ┌─────────────────┐
        │   Kubernetes    │
        │   • Services    │
        │   • ConfigMaps  │
        │   • Secrets     │
        │   • Deployments │
        └─────────────────┘
```

## 📋 Prerequisites

- **Java 17** or later
- **Maven 3.8** or later
- **Docker** for containerization
- **Kubernetes** cluster (minikube, kind, or cloud provider)
- **kubectl** configured to access your cluster

## 🚀 Quick Start

### 1. Clone and Build

```bash
# Clone the repository
git clone <repository-url>
cd test-jwt

# Build both applications
cd client-api
./mvnw clean package -DskipTests
cd ../server-api
./mvnw clean package -DskipTests
cd ..
```

### 2. Build Docker Images

```bash
# Build client-api image
docker build -t client-api:latest ./client-api/

# Build server-api image
docker build -t server-api:latest ./server-api/
```

### 3. Deploy to Kubernetes

```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployments.yaml
kubectl apply -f k8s/services.yaml

# Verify deployment
kubectl get pods
kubectl get services
```

### 4. Test the Application

```bash
# Forward port to access client-api
kubectl port-forward service/client-api 8080:8080 &

# Test health endpoint
curl http://localhost:8080/api/health

# Test encryption/decryption flow
curl -X POST http://localhost:8080/api/encrypt/message \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello, JWE World!"}'
```

## 📁 Project Structure

```
test-jwt/
├── client-api/                    # Client Spring Boot Application
│   ├── src/main/java/com/example/client/
│   │   ├── ClientApplication.java         # Main application class
│   │   ├── controller/
│   │   │   └── ClientController.java      # REST endpoints
│   │   └── service/
│   │       ├── JWEService.java           # JWE encryption service
│   │       └── ServerApiClient.java      # HTTP client for server
│   ├── src/main/resources/
│   │   └── application.yml               # Configuration
│   ├── Dockerfile                        # Container definition
│   └── pom.xml                          # Maven dependencies
├── server-api/                    # Server Spring Boot Application
│   ├── src/main/java/com/example/server/
│   │   ├── ServerApplication.java         # Main application class
│   │   ├── controller/
│   │   │   └── ServerController.java      # REST endpoints
│   │   └── service/
│   │       └── JWEService.java           # JWE decryption service
│   ├── src/main/resources/
│   │   └── application.yml               # Configuration
│   ├── Dockerfile                        # Container definition
│   └── pom.xml                          # Maven dependencies
├── k8s/                           # Kubernetes Manifests
│   ├── deployments.yaml                 # Application deployments
│   ├── services.yaml                    # Service definitions
│   ├── configmap.yaml                   # Configuration maps
│   └── secrets.yaml                     # JWE keys (base64 encoded)
└── README.md                      # This file
```

## 🔒 Security Features

### JWE Configuration

- **Algorithm**: RSA-OAEP-256 (Key Encryption)
- **Content Encryption**: A256GCM (Content Encryption)
- **Key Size**: 2048-bit RSA keys
- **Library**: Nimbus JOSE JWT

### Key Management

Keys are stored as Kubernetes Secrets and mounted as environment variables:

```yaml
env:
- name: JWE_CLIENT_PRIVATE_KEY
  valueFrom:
    secretKeyRef:
      name: jwe-keys
      key: client-private-key
```

### Container Security

- Non-root user execution
- Read-only root filesystem options
- Resource limits and requests
- Health checks and readiness probes

## 🔧 API Endpoints

### Client API (Port 8080)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/encrypt/message` | Encrypt message and send to server |
| GET | `/api/decrypt/{data}` | Decrypt provided JWE data |
| GET | `/api/health` | Health check endpoint |
| GET | `/api/public-key` | Get client's public key (dev only) |

### Server API (Port 8081)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/process` | Process encrypted message from client |
| GET | `/api/health` | Health check endpoint |
| GET | `/api/public-key` | Get server's public key |
| GET | `/api/info` | Server information |

## 🔄 Communication Flow

1. **Client Request**: User sends plaintext message to client-api
2. **Encryption**: Client encrypts message using server's public key (JWE)
3. **Transmission**: Encrypted message sent to server-api via HTTP
4. **Decryption**: Server decrypts message using its private key
5. **Processing**: Server processes the message (business logic)
6. **Response Encryption**: Server encrypts response using client's public key
7. **Response Decryption**: Client decrypts server response
8. **Result**: User receives processed plaintext response

## 📊 Example Usage

### Send Encrypted Message

```bash
curl -X POST http://localhost:8080/api/encrypt/message \
  -H "Content-Type: application/json" \
  -d '{
    "message": "This is a secret message that will be encrypted!"
  }'
```

**Response:**
```json
{
  "originalMessage": "This is a secret message that will be encrypted!",
  "encryptedMessage": "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0...",
  "serverResponse": "Server processed: 'This is a secret message...' at 2024-01-15T10:30:00",
  "status": "success"
}
```

### Health Check

```bash
curl http://localhost:8080/api/health
```

**Response:**
```json
{
  "status": "UP",
  "jweService": "UP",
  "serverApi": "UP",
  "timestamp": 1642248600000
}
```

## 🔑 Key Generation

The application automatically generates RSA key pairs on startup if not provided via environment variables. For production use, generate your own keys:

```bash
# Generate private key
openssl genpkey -algorithm RSA -out private_key.pem -pkcs8 -aes256

# Generate public key
openssl rsa -pubout -in private_key.pem -out public_key.pem

# Base64 encode for Kubernetes secrets
base64 -w 0 private_key.pem > private_key_b64.txt
base64 -w 0 public_key.pem > public_key_b64.txt
```

## 🐛 Troubleshooting

### Common Issues

1. **Pods not starting**:
   ```bash
   kubectl describe pod <pod-name>
   kubectl logs <pod-name>
   ```

2. **Service communication issues**:
   ```bash
   kubectl get services
   kubectl describe service client-api
   ```

3. **JWE key issues**:
   ```bash
   kubectl get secrets jwe-keys -o yaml
   ```

### Debugging

Enable debug logging by setting environment variable:
```yaml
env:
- name: LOGGING_LEVEL_COM_EXAMPLE
  value: DEBUG
```

### Port Forwarding for Local Testing

```bash
# Forward client-api
kubectl port-forward service/client-api 8080:8080

# Forward server-api
kubectl port-forward service/server-api 8081:8081
```

## 🌐 Production Considerations

### Security Enhancements

1. **Use HTTPS/TLS**: Configure TLS certificates for production
2. **Network Policies**: Implement Kubernetes network policies
3. **RBAC**: Set up proper role-based access control
4. **Secret Management**: Use external secret management (HashiCorp Vault, Azure Key Vault)
5. **Key Rotation**: Implement automated key rotation strategies

### Monitoring and Observability

1. **Metrics**: Enable Prometheus metrics via Spring Actuator
2. **Logging**: Centralized logging with ELK/Fluentd stack
3. **Tracing**: Distributed tracing with Jaeger/Zipkin
4. **Alerting**: Set up alerts for service health and security events

### High Availability

1. **Multi-replica**: Scale deployments across multiple nodes
2. **Pod Disruption Budgets**: Ensure service availability during updates
3. **Resource Quotas**: Set appropriate resource limits
4. **Auto-scaling**: Configure HPA (Horizontal Pod Autoscaler)

## 📚 Dependencies

### Core Dependencies

- **Spring Boot 3.2.0**: Application framework
- **Nimbus JOSE JWT 9.37.3**: JWE/JWT operations
- **Spring Boot Actuator**: Health checks and metrics
- **Jackson**: JSON processing

### Build Dependencies

- **Maven 3.9.5**: Build tool
- **OpenJDK 17**: Runtime environment

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Spring Boot team for the excellent framework
- Nimbus team for the JOSE JWT library
- Kubernetes community for container orchestration

---

**Note**: This is a demonstration project. For production use, ensure proper security reviews, key management, and compliance with your organization's security policies.
