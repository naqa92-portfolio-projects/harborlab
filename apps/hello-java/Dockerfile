# Built and run on the golden java JRE. It has no shell and no javac: Maven runs through its wrapper
# jar in exec form and compiles with the Eclipse compiler (see pom.xml).
FROM ghcr.io/naqa92-portfolio-projects/harborlab/golden/java@sha256:d90b2f34d8725f8fcfbd4e9e1c9ba0b85bfe1c26497e2c9cb7bc45aacfc6318b AS build
ENV MAVEN_USER_HOME=/tmp/m2
COPY --chown=65532:65532 . /tmp/build/
# The wrapper reads maven-wrapper.properties next to its jar.
ADD --checksum=sha256:4e2fbf6554bc8a4702cdfdd3bef464f423393d784ddbb037216320ce55d5e4e1 --chown=65532:65532 \
    https://repo1.maven.org/maven2/org/apache/maven/wrapper/maven-wrapper/3.3.4/maven-wrapper-3.3.4.jar \
    /tmp/build/.mvn/wrapper/maven-wrapper.jar
RUN ["java", "-classpath", "/tmp/build/.mvn/wrapper/maven-wrapper.jar", "-Dmaven.multiModuleProjectDirectory=/tmp/build", \
     "org.apache.maven.wrapper.MavenWrapperMain", "--batch-mode", "--no-transfer-progress", \
     "--file", "/tmp/build/pom.xml", "-Dmaven.repo.local=/tmp/m2/repository", "package"]

FROM ghcr.io/naqa92-portfolio-projects/harborlab/golden/java@sha256:d90b2f34d8725f8fcfbd4e9e1c9ba0b85bfe1c26497e2c9cb7bc45aacfc6318b
LABEL org.opencontainers.image.title="hello-java" \
      org.opencontainers.image.description="Golden-path Spring Boot application of the harborlab platform"
COPY --from=build /tmp/build/target/hello-java.jar /app/hello-java.jar
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/hello-java.jar"]
