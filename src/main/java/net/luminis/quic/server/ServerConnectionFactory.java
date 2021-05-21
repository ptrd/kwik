/*
 * Copyright © 2020, 2021 Peter Doornbosch
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
package net.luminis.quic.server;

import net.luminis.quic.Version;
import net.luminis.quic.log.Logger;
import net.luminis.tls.handshake.TlsServerEngineFactory;

import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.function.Consumer;


public class ServerConnectionFactory {

    private final int connectionIdLength;
    private final Logger log;
    private final TlsServerEngineFactory tlsServerEngineFactory;
    private final ApplicationProtocolRegistry applicationProtocolRegistry;
    private final DatagramSocket serverSocket;
    private final int initalRtt;
    private final SecureRandom randomGenerator;
    private final Consumer<byte[]> closeCallback;
    private final boolean requireRetry;

    public ServerConnectionFactory(int connectionIdLength, DatagramSocket serverSocket, TlsServerEngineFactory tlsServerEngineFactory,
                                   boolean requireRetry, ApplicationProtocolRegistry applicationProtocolRegistry, int initalRtt, Consumer<byte[]> closeCallback, Logger log) {
        if (connectionIdLength > 20 || connectionIdLength < 0) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2
            // "In QUIC version 1, this value MUST NOT exceed 20 bytes"
            throw new IllegalArgumentException();
        }
        this.tlsServerEngineFactory = tlsServerEngineFactory;
        this.requireRetry = requireRetry;
        this.applicationProtocolRegistry = applicationProtocolRegistry;
        this.connectionIdLength = connectionIdLength;
        this.closeCallback = closeCallback;
        this.log = log;
        this.serverSocket = serverSocket;
        this.initalRtt = initalRtt;

        randomGenerator = new SecureRandom();
    }

    public ServerConnectionImpl createNewConnection(Version version, InetSocketAddress clientAddress, byte[] originalScid, byte[] originalDcid) {
        byte[] connectionId = generateNewConnectionId();
        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-7.2
        // "A server MUST set the Destination Connection ID it uses for sending packets based on the first received Initial packet."
        byte[] dcid = originalScid;
        return new ServerConnectionImpl(version, serverSocket, clientAddress, connectionId, dcid, originalDcid,
                tlsServerEngineFactory, requireRetry, applicationProtocolRegistry, initalRtt, closeCallback, log);
    }

    private byte[] generateNewConnectionId() {
        byte[] connectionId = new byte[connectionIdLength];
        randomGenerator.nextBytes(connectionId);
        return connectionId;
    }
}
