/*
 * Copyright © 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.packet;

import java.net.InetSocketAddress;
import java.time.Instant;

public class PacketMetaData {

    private final Instant timeReceived;
    private final InetSocketAddress sourceAddress;
    private final int datagramNumber;
    private final int datagramSize;
    private final boolean moreDataInDatagram;

    public PacketMetaData(Instant timeReceived, InetSocketAddress sourceAddress, int datagramNumber, int datagramSize) {
        this.timeReceived = timeReceived;
        this.sourceAddress = sourceAddress;
        this.datagramNumber = datagramNumber;
        this.datagramSize = datagramSize;
        moreDataInDatagram = false;
    }

    public PacketMetaData(PacketMetaData original, boolean moreDataInDatagram) {
        this.timeReceived = original.timeReceived;
        this.sourceAddress = original.sourceAddress;
        this.datagramNumber = original.datagramNumber;
        this.datagramSize = original.datagramSize;
        this.moreDataInDatagram = moreDataInDatagram;
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

    public int getDatagramSize() {
        return datagramSize;
    }

    public int datagramNumber() {
        return datagramNumber;
    }
}
