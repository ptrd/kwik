/*
 * Copyright © 2020, 2021, 2022, 2023 Peter Doornbosch
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

import net.luminis.quic.core.Version;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.InitialPacket;
import net.luminis.tls.handshake.TlsServerEngineFactory;

import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.function.Consumer;

import static net.luminis.quic.server.Constants.MAXIMUM_CONNECTION_ID_LENGTH;
import static net.luminis.quic.server.Constants.MINIMUM_CONNECTION_ID_LENGTH;


public class ServerConnectionFactory {

    private final Logger log;
    private final TlsServerEngineFactory tlsServerEngineFactory;
    private final ApplicationProtocolRegistry applicationProtocolRegistry;
    private final DatagramSocket serverSocket;
    private final Consumer<ServerConnectionImpl> closeCallback;
    private final ServerConnectionRegistry connectionRegistry;
    private final ServerConfig configuration;

    public ServerConnectionFactory(DatagramSocket serverSocket, TlsServerEngineFactory tlsServerEngineFactory,
                                   ServerConfig configuration, ApplicationProtocolRegistry applicationProtocolRegistry,
                                   ServerConnectionRegistry connectionRegistry, Consumer<ServerConnectionImpl> closeCallback, Logger log)
    {
        if (configuration.connectionIdLength() > MAXIMUM_CONNECTION_ID_LENGTH || configuration.connectionIdLength() < MINIMUM_CONNECTION_ID_LENGTH) {
            throw new IllegalArgumentException();
        }
        this.tlsServerEngineFactory = tlsServerEngineFactory;
        this.configuration = configuration;
        this.applicationProtocolRegistry = applicationProtocolRegistry;
        this.connectionRegistry = connectionRegistry;
        this.closeCallback = closeCallback;
        this.log = log;
        this.serverSocket = serverSocket;
    }

    /**
     * Creates new server connection.
     * @param version  quic version used
     * @param clientAddress  the address of the client
     * @param scid  the source connection id used by the client
     * @param originalDcid  the original destination id used by the client
     * @return
     */
    public ServerConnectionImpl createNewConnection(Version version, InetSocketAddress clientAddress, byte[] scid, byte[] originalDcid) {
        return new ServerConnectionImpl(version, serverSocket, clientAddress, scid, originalDcid,
                tlsServerEngineFactory, configuration, applicationProtocolRegistry, connectionRegistry, closeCallback, log);
    }

    public ServerConnectionProxy createServerConnectionProxy(ServerConnectionImpl connection, InitialPacket initialPacket, Instant packetReceived, ByteBuffer datagram) {
        return new ServerConnectionThread(connection, initialPacket, packetReceived, datagram);
    }
}
