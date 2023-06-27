# Use an OpenJDK base image
FROM maven:3.8.4-openjdk-17 as builder

# Set the working directory inside the container
WORKDIR /app

# Copy the Maven project files
COPY pom.xml .

# Resolve Maven dependencies (to cache them)
RUN mvn dependency:go-offline -B

# Copy the application source code
COPY src src

# Build the application
RUN mvn package -DskipTests

# Use a slim OpenJDK base image for the final image
FROM openjdk:17-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the Spring Boot application JAR file from the builder stage
COPY --from=builder /app/target/kotlin-k8s-public-key-cryptography-0.0.1-SNAPSHOT.jar .

# Create the necessary directory structure
RUN mkdir -p /app/src/main/resources

# Expose the port on which your Spring Boot application will listen
EXPOSE 8080

# Set the command to run your Spring Boot application
CMD ["java", "-jar", "kotlin-k8s-public-key-cryptography-0.0.1-SNAPSHOT.jar"]