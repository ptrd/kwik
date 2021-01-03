FROM openjdk:11

COPY build/libs/kwik.jar .
COPY test.kwik.tech.pem cert.pem
COPY test.kwik.tech.key key.pem
RUN mkdir /logs
RUN mkdir /logs/qlog
ENV QLOGDIR=/logs/qlog
RUN mkdir /www
COPY kwikindex.html /www/index.html
RUN truncate -s 50K /www/50K
RUN truncate -s 100K /www/100K
RUN truncate -s 500K /www/500K
RUN truncate -s 1M /www/1M
RUN truncate -s 2M /www/2M
RUN truncate -s 3M /www/3M
RUN truncate -s 4M /www/4M
RUN truncate -s 5M /www/5M

CMD [ "java", "-cp", "kwik.jar", "net.luminis.quic.server.Server", "cert.pem", "key.pem", "4433", "/www" ]
