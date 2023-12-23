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
package net.luminis.quic.server.h09;

import net.luminis.quic.QuicConnection;
import net.luminis.quic.server.ApplicationProtocolConnection;
import net.luminis.quic.server.ApplicationProtocolConnectionFactory;

import java.io.File;

public class Http09ApplicationProtocolFactory implements ApplicationProtocolConnectionFactory {

    private File wwwDir;

    public Http09ApplicationProtocolFactory(File wwwDir) {
        if (wwwDir == null) {
            throw new IllegalArgumentException();
        }
        this.wwwDir = wwwDir;
    }

    @Override
    public int maxConcurrentUnidirectionalStreams() {
        return 0;
    }

    @Override
    public int maxConcurrentBidirectionalStreams() {
        return 100;
    }

    @Override
    public ApplicationProtocolConnection createConnection(String protocol, QuicConnection quicConnection) {
        return new Http09Connection(quicConnection, wwwDir);
    }
}
