FROM openjdk:11

COPY build/libs/kwik.jar .
COPY test.kwik.tech.pem cert.pem
COPY test.kwik.tech.key key.pem
RUN mkdir /logs
RUN mkdir /www
COPY kwikindex.html /www/index.html

CMD [ "java", "-cp", "kwik.jar", "net.luminis.quic.server.Server", "cert.pem", "key.pem", "4433", "/www" ]
