/*
 * Copyright © 2019, 2020 Peter Doornbosch
 *
 * This file is part of Kwik, a QUIC client Java library
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
package net.luminis.quic;

import java.util.Objects;

public class PacketId implements Comparable<PacketId> {

    private final PnSpace pnSpace;
    private final long packetNumber;

    public PacketId(PnSpace pnSpace, long packetNumber) {
        this.pnSpace = pnSpace;
        this.packetNumber = packetNumber;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PacketId packetId = (PacketId) o;
        return packetNumber == packetId.packetNumber &&
                pnSpace == packetId.pnSpace;
    }

    @Override
    public int hashCode() {
        return Objects.hash(pnSpace, packetNumber);
    }

    @Override
    public String toString() {
        return pnSpace.name().charAt(0) + "|" + packetNumber;
    }

    @Override
    public int compareTo(PacketId other) {
        if (this.pnSpace.ordinal() < other.pnSpace.ordinal()) {
            return -1;
        }
        else if (this.pnSpace.ordinal() > other.pnSpace.ordinal()) {
            return 1;
        }
        else {
            return Long.compare(this.packetNumber, other.packetNumber);
        }
    }
}
