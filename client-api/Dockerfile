#########################################
# Multi-stage Dockerfile
# Builder: maven with JDK 17
# Runtime: Eclipse Temurin JRE 17 (lightweight)
#########################################

# Builder stage
FROM maven:3.9.5-eclipse-temurin-17 as builder
WORKDIR /build
COPY pom.xml ./
COPY .mvn .mvn
COPY src src
# Use the Maven installed in the builder image directly to avoid wrapper env issues
RUN mvn -q -DskipTests clean package

# Runtime stage
FROM eclipse-temurin:17-jre
WORKDIR /app
RUN addgroup --system appuser && adduser --system --ingroup appuser appuser || true
COPY --from=builder /build/target/*.jar app.jar
RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]
CMD ["--spring.profiles.active=kubernetes"]
