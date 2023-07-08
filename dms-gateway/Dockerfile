#FROM openjdk:8-jre-alpine
FROM amazoncorretto:alpine:3.17


RUN addgroup -S spring && adduser -S spring -G spring

RUN  apk update
RUN  apk add tzdata

USER spring:spring
ARG JAR_FILE=target/*.jar

COPY ${JAR_FILE} /dms-gateway.jar
RUN ls -al /
#ENTRYPOINT ["java", "-jar", "--spring.config.location=file:/my_data/config/dms-gateway.yml", "/dms-gateway.jar"]
ENTRYPOINT ["java", "-jar", "-Dspring.profiles.active=dev", "/dms-gateway.jar"]
#ENTRYPOINT ["java", "-Xdebug", "-Xrunjdwp:transport=dt_socket,address=5005,server=y,suspend=y", "-Dspring.profiles.active=dev", "-jar", "/dms.jar"]