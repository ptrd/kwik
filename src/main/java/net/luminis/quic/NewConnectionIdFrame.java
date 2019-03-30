/*
 * Copyright © 2019 Peter Doornbosch
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

import java.nio.ByteBuffer;

public class NewConnectionIdFrame extends QuicFrame {

    private Version quicVersion;
    private int sequenceNr;
    private byte[] connectionId;

    public NewConnectionIdFrame(Version quicVersion) {
        this.quicVersion = quicVersion;
    }

    @Override
    byte[] getBytes() {
        return new byte[0];
    }

    public NewConnectionIdFrame parse(ByteBuffer buffer, Logger log) {
        buffer.get();

        if (quicVersion.equals(Version.IETF_draft_14) || quicVersion.atLeast(Version.IETF_draft_17)) {
            sequenceNr = QuicPacket.parseVariableLengthInteger(buffer);
            int connectionIdLength = buffer.get();
            connectionId = new byte[connectionIdLength];
            buffer.get(connectionId);
        }
        else if (quicVersion.atLeast(Version.IETF_draft_15)) {
            int connectionIdLength = buffer.get();
            sequenceNr = QuicPacket.parseVariableLengthInteger(buffer);
            connectionId = new byte[connectionIdLength];
            buffer.get(connectionId);
        }

        byte[] statelessResetToken = new byte[128 / 8];
        buffer.get(statelessResetToken);

        return this;
    }

    @Override
    public String toString() {
        return "NewConnectionIdFrame[" + sequenceNr + "]";
    }

    public int getSequenceNr() {
        return sequenceNr;
    }

    public byte[] getConnectionId() {
        return connectionId;
    }

}
