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
package net.luminis.quic.packet;

import java.net.InetSocketAddress;
import java.time.Instant;

public class PacketMetaData {

    private final Instant timeReceived;
    private final InetSocketAddress sourceAddress;
    private final int datagramNumber;
    private final boolean moreDataInDatagram;

    public PacketMetaData(Instant timeReceived) {
        this.timeReceived = timeReceived;
        moreDataInDatagram = false;
        sourceAddress = null;
        datagramNumber = -1;
    }

    public PacketMetaData(Instant timeReceived, boolean moreDataInDatagram) {
        this.timeReceived = timeReceived;
        this.moreDataInDatagram = moreDataInDatagram;
        sourceAddress = null;
        datagramNumber = -1;
    }

    public PacketMetaData(Instant timeReceived, InetSocketAddress sourceAddress, int datagramNumber) {
        this.timeReceived = timeReceived;
        this.sourceAddress = sourceAddress;
        this.datagramNumber = datagramNumber;
        moreDataInDatagram = false;
    }

    public Instant timeReceived() {
        return timeReceived;
    }

    public boolean moreDataInDatagram() {
        return moreDataInDatagram;
    }

    public InetSocketAddress sourceAddress() {
        return sourceAddress;
    }

    public int datagramNumber() {
        return datagramNumber;
    }
}
