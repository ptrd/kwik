/*
 * Copyright © 2021 Peter Doornbosch
 *
 * This file is part of Kwik, an implementation of the QUIC protocol in Java.
 *
 * Kwik is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Kwik is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package net.luminis.quic.client.h09;

import net.luminis.quic.QuicClientConnection;
import net.luminis.quic.stream.QuicStream;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.io.InputStream;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.Flow;

/**
 * A HTTP client for HTTP 0.9 requests.
 * See
 * <ul>
 * <li>https://www.w3.org/Protocols/HTTP/AsImplemented.html</li>
 * <li>https://superuser.com/questions/1504500/what-is-http-0-9-request</li>
 * </ul>
 */
public class Http09Client extends HttpClient {

    private final QuicClientConnection quicConnection;
    private final int connectionTimeout = 10_000;

    public Http09Client(QuicClientConnection quicConnection) {
        this.quicConnection = quicConnection;
    }

    @Override
    public Optional<CookieHandler> cookieHandler() {
        return Optional.empty();
    }

    @Override
    public Optional<Duration> connectTimeout() {
        return Optional.empty();
    }

    @Override
    public Redirect followRedirects() {
        return null;
    }

    @Override
    public Optional<ProxySelector> proxy() {
        return Optional.empty();
    }

    @Override
    public SSLContext sslContext() {
        return null;
    }

    @Override
    public SSLParameters sslParameters() {
        return null;
    }

    @Override
    public Optional<Authenticator> authenticator() {
        return Optional.empty();
    }

    @Override
    public Version version() {
        return null;
    }

    @Override
    public Optional<Executor> executor() {
        return Optional.empty();
    }

    @Override
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler) throws IOException, InterruptedException {
        if (!quicConnection.isConnected()) {
            String alpn;
            if (quicConnection.getQuicVersion().equals(net.luminis.quic.Version.QUIC_version_1)) {
                alpn = "hq-interop";
            } else {
                String draftVersion = quicConnection.getQuicVersion().getDraftVersion();
                alpn = "hq-" + draftVersion;
            }
            quicConnection.connect(connectionTimeout, alpn, null, null);
        }

        boolean bidirectional = true;
        QuicStream httpStream = quicConnection.createStream(bidirectional);
        String requestPath = request.uri().getPath();
        httpStream.getOutputStream().write(("GET " + requestPath + "\r\n").getBytes());
        httpStream.getOutputStream().close();

        HttpResponse.BodySubscriber<T> bodySubscriber = responseBodyHandler.apply(new HttpResponse.ResponseInfo() {
            @Override
            public int statusCode() {
                return 200;
            }

            @Override
            public HttpHeaders headers() {
                return HttpHeaders.of(Collections.emptyMap(), (u, v) -> true);
            }

            @Override
            public Version version() {
                return null;
            }
        });

        bodySubscriber.onSubscribe(new Flow.Subscription() {
            @Override
            public void request(long n) {}

            @Override
            public void cancel() {}
        });

        InputStream inputStream = httpStream.getInputStream();
        while (true) {
            int available = inputStream.available();
            if (available == 0) {
                available = 1;  // Wait for more data
            }
            byte[] buffer = new byte[available];
            int read = inputStream.read(buffer);
            if (read < 0) {
                break;
            }
            bodySubscriber.onNext(List.of(ByteBuffer.wrap(buffer, 0, read)));
        }
        bodySubscriber.onComplete();

        try {
            T body = bodySubscriber.getBody().toCompletableFuture().get();
            return new HttpResponseImpl(request, body);
        } catch (ExecutionException e) {
            throw new IOException(e);
        }
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler) {
        throw new UnsupportedOperationException();
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler, HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
        throw new UnsupportedOperationException();
    }
}
