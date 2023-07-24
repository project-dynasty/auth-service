# Build stage
FROM maven:3.8.6-openjdk-11-slim AS build
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline
COPY src/ /app/src/
RUN mvn clean package -DskipTests

# Production stage
FROM adoptopenjdk/openjdk11:jdk-11.0.20_8-alpine
WORKDIR /app
COPY --from=build /app/target/auth-service-jar-with-dependencies.jar app.jar
EXPOSE 6472
EXPOSE 3345
ENTRYPOINT ["java", "-jar", "app.jar"]