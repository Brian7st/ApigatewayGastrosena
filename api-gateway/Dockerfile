# Runtime-only: el jar se construye antes en el host porque el gateway depende
# de las libs locales ga-lib-security / ga-lib-common (SNAPSHOT en el .m2 local).
#
# Build (desde apiGatway-2/api-gateway):
#   ./mvnw -DskipTests clean package
# Requiere haber instalado antes las libs:
#   (en ga-lib-common)   ./mvnw -DskipTests install
#   (en ga-lib-security) ./mvnw -DskipTests install
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY target/api-gateway-0.0.1-SNAPSHOT.jar app.jar
EXPOSE 8088
ENTRYPOINT ["java", "-jar", "app.jar"]
