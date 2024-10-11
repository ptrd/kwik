/*
 * Copyright © 2024 Peter Doornbosch
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
package net.luminis.quic.impl;

/**
 * Datagram extension as specified by RFC 9221 "An Unreliable Datagram Extension to QUIC".
 * https://www.rfc-editor.org/rfc/rfc9221.html#name-datagram-frame-types
 */
public interface DatagramExtension {

    boolean canSendDatagram();

    boolean canReceiveDatagram();

    /**
     * Returns whether the datagram extension is enabled for this connection, which means that the peer has indicated
     * support for the datagram extension and the local endpoint has enabled it ("can send", "can receive").
     * @return
     */
    boolean isDatagramExtensionEnabled();

    /**
     * The maximum size of the data that can be sent in a single datagram.
     * @return
     */
    int maxDatagramDataSize();

    void sendDatagram(byte[] data);

}
