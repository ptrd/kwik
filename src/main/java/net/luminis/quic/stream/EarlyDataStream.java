/*
 * Copyright © 2020 Peter Doornbosch
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
package net.luminis.quic.stream;

import net.luminis.quic.QuicConnectionImpl;
import net.luminis.quic.Version;
import net.luminis.quic.frame.StreamFrame;
import net.luminis.quic.log.Logger;

/**
 * A quic stream that is capable of sending early data. When early data is offered but cannot be send as early data,
 * the data will be cached until it can be send.
 */
public class EarlyDataStream extends QuicStream {

    public EarlyDataStream(Version quicVersion, int streamId, QuicConnectionImpl connection, FlowControl flowController, Logger log) {
        super(quicVersion, streamId, connection, flowController, log);
    }

    /**
     * Write early data, assuming the provided data is complete and fits into one StreamFrame.
     * @param earlyData
     */
    public void writeEarlyData(byte[] earlyData, boolean fin) {
        if (earlyData.length > 1000) {
            log.error("0-RTT data is limited to 1000 bytes.");
            return;
        }
        // TODO: to make this more generally applicable (not just for http (09) requests:
        // - do not assume stream is complete, i.e. make explicit whether output must be closed or not
        // - update output stream offset
        // - update (and respect) flow control
        // - accept more data (up to server initial max data)
        log.info("sending early data now");
        connection.sendEarlyData(new StreamFrame(quicVersion, streamId, 0, earlyData, 0, earlyData.length, fin), f -> {});
    }


}

