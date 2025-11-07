#!/bin/bash

# JWE Demo Build and Deploy Script
# This script builds the applications, creates Docker images, and deploys to Kubernetes

set -e

echo "🚀 Starting JWE Demo Build and Deploy Process..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

function print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

function print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

function print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
check_command() {
    if ! command -v $1 &> /dev/null; then
        print_error "$1 is required but not installed. Please install $1."
        exit 1
    fi
}

# Check prerequisites
print_status "Checking prerequisites..."
check_command "java"
check_command "docker"
check_command "kubectl"

# Check Java version
JAVA_VERSION=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}' | cut -d'.' -f1)
if [ "$JAVA_VERSION" -lt 17 ]; then
    print_error "Java 17 or later is required. Current version: $JAVA_VERSION"
    exit 1
fi

print_status "Prerequisites check passed!"

# Build client-api
print_status "Building client-api..."
cd client-api
./mvnw clean package -DskipTests
if [ $? -eq 0 ]; then
    print_status "Client API build successful!"
else
    print_error "Client API build failed!"
    exit 1
fi
cd ..

# Build server-api
print_status "Building server-api..."
cd server-api
./mvnw clean package -DskipTests
if [ $? -eq 0 ]; then
    print_status "Server API build successful!"
else
    print_error "Server API build failed!"
    exit 1
fi
cd ..

# Build Docker images
print_status "Building Docker images..."

print_status "Building client-api Docker image..."
docker build -t client-api:latest ./client-api/
if [ $? -eq 0 ]; then
    print_status "Client API Docker image built successfully!"
else
    print_error "Client API Docker build failed!"
    exit 1
fi

print_status "Building server-api Docker image..."
docker build -t server-api:latest ./server-api/
if [ $? -eq 0 ]; then
    print_status "Server API Docker image built successfully!"
else
    print_error "Server API Docker build failed!"
    exit 1
fi

# Check Kubernetes connectivity
print_status "Checking Kubernetes connectivity..."
if ! kubectl cluster-info &> /dev/null; then
    print_error "Unable to connect to Kubernetes cluster. Please check your kubectl configuration."
    exit 1
fi

print_status "Kubernetes cluster accessible!"

# Deploy to Kubernetes
print_status "Deploying to Kubernetes..."

print_status "Ensuring namespace exists..."
# create namespace manifest (idempotent)
kubectl apply -f k8s/namespace.yaml

print_status "Applying secrets..."
kubectl apply -f k8s/secrets.yaml -n jwt-demo

print_status "Applying configmaps..."
kubectl apply -f k8s/configmap.yaml -n jwt-demo

print_status "Applying deployments..."
kubectl apply -f k8s/deployments.yaml -n jwt-demo

print_status "Applying services..."
kubectl apply -f k8s/services.yaml -n jwt-demo

# Wait for deployments to be ready
print_status "Waiting for deployments to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/client-api
kubectl wait --for=condition=available --timeout=300s deployment/server-api

# Show deployment status
print_status "Deployment Status:"
kubectl get pods -l app=client-api
kubectl get pods -l app=server-api
kubectl get services

print_status "🎉 JWE Demo deployment completed successfully!"

echo ""
print_warning "To test the application, run the following commands:"
echo "kubectl port-forward service/client-api 8080:8080 &"
echo "curl -X POST http://localhost:8080/api/encrypt/message -H 'Content-Type: application/json' -d '{\"message\": \"Hello JWE World!\"}'"

echo ""
print_status "For more testing examples, see README.md"
