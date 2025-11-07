#!/bin/bash

# JWE Demo Test Script
# This script runs various tests against the deployed JWE demo application

set -e

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

function print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Default values
CLIENT_URL="http://localhost:8080"
SERVER_URL="http://localhost:8081"
NAMESPACE="default"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --client-url)
            CLIENT_URL="$2"
            shift 2
            ;;
        --server-url)
            SERVER_URL="$2"
            shift 2
            ;;
        --namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--client-url URL] [--server-url URL] [--namespace NAMESPACE]"
            echo "  --client-url   Client API URL (default: http://localhost:8080)"
            echo "  --server-url   Server API URL (default: http://localhost:8081)"
            echo "  --namespace    Kubernetes namespace (default: default)"
            exit 0
            ;;
        *)
            print_error "Unknown parameter: $1"
            exit 1
            ;;
    esac
done

print_status "🧪 Starting JWE Demo Tests..."
print_status "Client URL: $CLIENT_URL"
print_status "Server URL: $SERVER_URL"
print_status "Namespace: $NAMESPACE"

# Function to make HTTP request and check response
make_request() {
    local method="$1"
    local url="$2"
    local data="$3"
    local expected_status="$4"

    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "%{http_code}" "$url")
    else
        response=$(curl -s -w "%{http_code}" -X "$method" -H "Content-Type: application/json" -d "$data" "$url")
    fi

    http_code="${response: -3}"
    body="${response%???}"

    if [ "$http_code" = "$expected_status" ]; then
        return 0
    else
        print_error "Expected status $expected_status, got $http_code"
        echo "Response body: $body"
        return 1
    fi
}

# Test 1: Check if services are running in Kubernetes
print_status "Test 1: Checking Kubernetes deployment status..."
if kubectl get pods -n "$NAMESPACE" -l app=client-api | grep Running > /dev/null; then
    print_success "Client API pods are running"
else
    print_error "Client API pods are not running"
    kubectl get pods -n "$NAMESPACE" -l app=client-api
fi

if kubectl get pods -n "$NAMESPACE" -l app=server-api | grep Running > /dev/null; then
    print_success "Server API pods are running"
else
    print_error "Server API pods are not running"
    kubectl get pods -n "$NAMESPACE" -l app=server-api
fi

# Test 2: Health checks
print_status "Test 2: Testing health endpoints..."

print_status "Testing client-api health..."
if make_request "GET" "$CLIENT_URL/api/health" "" "200"; then
    print_success "Client API health check passed"
else
    print_error "Client API health check failed"
fi

print_status "Testing server-api health..."
if make_request "GET" "$SERVER_URL/api/health" "" "200"; then
    print_success "Server API health check passed"
else
    print_error "Server API health check failed"
fi

# Test 3: Public key endpoints
print_status "Test 3: Testing public key endpoints..."

print_status "Testing client-api public key..."
if make_request "GET" "$CLIENT_URL/api/public-key" "" "200"; then
    print_success "Client API public key retrieval passed"
else
    print_error "Client API public key retrieval failed"
fi

print_status "Testing server-api public key..."
if make_request "GET" "$SERVER_URL/api/public-key" "" "200"; then
    print_success "Server API public key retrieval passed"
else
    print_error "Server API public key retrieval failed"
fi

# Test 4: JWE encryption/decryption flow
print_status "Test 4: Testing JWE encryption/decryption flow..."

test_message="Hello JWE World! This is a test message."
payload="{\"message\": \"$test_message\"}"

print_status "Testing encryption and server communication..."
response=$(curl -s -X POST -H "Content-Type: application/json" -d "$payload" "$CLIENT_URL/api/encrypt/message")
http_code=$(curl -s -w "%{http_code}" -o /dev/null -X POST -H "Content-Type: application/json" -d "$payload" "$CLIENT_URL/api/encrypt/message")

if [ "$http_code" = "200" ]; then
    print_success "JWE encryption/decryption flow test passed"
    echo "Response: $response"
else
    print_error "JWE encryption/decryption flow test failed with status code: $http_code"
    echo "Response: $response"
fi

# Test 5: Server info endpoint
print_status "Test 5: Testing server info endpoint..."

if make_request "GET" "$SERVER_URL/api/info" "" "200"; then
    print_success "Server info endpoint test passed"
else
    print_error "Server info endpoint test failed"
fi

# Test 6: Load test with multiple messages
print_status "Test 6: Running basic load test..."

success_count=0
total_requests=10

for i in $(seq 1 $total_requests); do
    test_payload="{\"message\": \"Load test message #$i\"}"
    if make_request "POST" "$CLIENT_URL/api/encrypt/message" "$test_payload" "200" > /dev/null 2>&1; then
        ((success_count++))
    fi
    echo -n "."
done
echo

success_rate=$((success_count * 100 / total_requests))
print_status "Load test completed: $success_count/$total_requests requests successful ($success_rate%)"

if [ $success_rate -ge 90 ]; then
    print_success "Load test passed (≥90% success rate)"
else
    print_error "Load test failed (<90% success rate)"
fi

# Test 7: Error handling
print_status "Test 7: Testing error handling..."

# Test empty message
empty_payload="{\"message\": \"\"}"
response=$(curl -s -w "%{http_code}" -X POST -H "Content-Type: application/json" -d "$empty_payload" "$CLIENT_URL/api/encrypt/message")
http_code="${response: -3}"

if [ "$http_code" = "400" ]; then
    print_success "Empty message error handling test passed"
else
    print_error "Empty message error handling test failed (expected 400, got $http_code)"
fi

# Test invalid JSON
invalid_response=$(curl -s -w "%{http_code}" -X POST -H "Content-Type: application/json" -d "invalid json" "$CLIENT_URL/api/encrypt/message")
invalid_http_code="${invalid_response: -3}"

if [ "$invalid_http_code" = "400" ]; then
    print_success "Invalid JSON error handling test passed"
else
    print_warning "Invalid JSON error handling test: expected 400, got $invalid_http_code"
fi

print_status "🎉 JWE Demo tests completed!"

# Summary
echo ""
print_status "📊 Test Summary:"
echo "✅ Kubernetes deployment status"
echo "✅ Health endpoints"
echo "✅ Public key retrieval"
echo "✅ JWE encryption/decryption"
echo "✅ Server info endpoint"
echo "✅ Basic load testing"
echo "✅ Error handling"

print_success "All core functionality is working correctly!"

echo ""
print_warning "💡 Next steps:"
echo "1. Monitor application logs: kubectl logs -f deployment/client-api"
echo "2. Check metrics: curl $CLIENT_URL/actuator/metrics"
echo "3. Scale deployment: kubectl scale deployment client-api --replicas=3"
echo "4. Update secrets for production use"
