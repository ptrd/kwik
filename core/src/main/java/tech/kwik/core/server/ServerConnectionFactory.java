/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.server;

import tech.kwik.agent15.engine.TlsServerEngineFactory;
import tech.kwik.core.crypto.CryptoStream;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.InitialPacket;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.server.impl.ApplicationProtocolRegistry;
import tech.kwik.core.server.impl.ServerConnectionImpl;
import tech.kwik.core.server.impl.ServerConnectionProxy;
import tech.kwik.core.server.impl.ServerConnectionThread;
import tech.kwik.core.util.Bytes;

import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.function.Consumer;

import static tech.kwik.core.server.Constants.MAXIMUM_CONNECTION_ID_LENGTH;
import static tech.kwik.core.server.Constants.MINIMUM_CONNECTION_ID_LENGTH;


public class ServerConnectionFactory {

    private final Logger log;
    private final TlsServerEngineFactory tlsServerEngineFactory;
    private final ApplicationProtocolRegistry applicationProtocolRegistry;
    private final DatagramSocket serverSocket;
    private final Consumer<ServerConnectionImpl> closeCallback;
    private final ServerConnectionRegistry connectionRegistry;
    private final ServerConnectionConfig configuration;

    public ServerConnectionFactory(DatagramSocket serverSocket, TlsServerEngineFactory tlsServerEngineFactory,
                                   ServerConnectionConfig configuration, ApplicationProtocolRegistry applicationProtocolRegistry,
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
     *
     * @param version       quic version used
     * @param clientAddress the address of the client
     * @param scid          the source connection id used by the client
     * @param originalDcid  the original destination id used by the client
     * @param cryptoStream  stream containing crypto data already received on encryption level Initial
     * @return
     */
    public ServerConnectionImpl createNewConnection(Version version, InetSocketAddress clientAddress, byte[] scid, byte[] originalDcid, CryptoStream cryptoStream) {
        ServerConnectionImpl connection = new ServerConnectionImpl(version, serverSocket, clientAddress, scid, originalDcid, cryptoStream,
                tlsServerEngineFactory, configuration, applicationProtocolRegistry, connectionRegistry, closeCallback, log);

        log.info("Creating new connection with version " + version + " for odcid " + Bytes.bytesToHex(originalDcid)
                + " with " + clientAddress.getAddress().getHostAddress() + ": " + Bytes.bytesToHex(connection.getInitialConnectionId()));

        return connection;
    }

    public ServerConnectionProxy createServerConnectionProxy(ServerConnectionImpl connection, List<InitialPacket> initialPackets, ByteBuffer data, PacketMetaData metaData) {
        return new ServerConnectionThread(connection, initialPackets, data, metaData, log);
    }
}
