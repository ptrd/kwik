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
package tech.kwik.core.stream;

import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.impl.QuicClientConnectionImpl;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;

import java.io.IOException;
import java.util.Arrays;


/**
 * A quic stream that is capable of sending early data. When early data is offered but cannot be send as early data,
 * the data will be cached until it can be send.
 */
public class EarlyDataStream extends QuicStreamImpl {

    private final FlowControl flowController;
    private volatile boolean sendingEarlyData = true;
    private boolean earlyDataIsFinalInStream;
    private byte[] earlyData = new byte[0];
    private byte[] remainingData = new byte[0];
    private boolean writingEarlyData = true;
    private volatile boolean earlyDataSent;
    private volatile boolean finalFrameSent;


    public EarlyDataStream(Version quicVersion, int streamId, QuicClientConnectionImpl connection, StreamManager streamManager, FlowControl flowController, Logger log) {
        super(quicVersion, streamId, Role.Client, connection, streamManager, flowController, log);
        this.flowController = flowController;
    }

    /**
     * Write early data, keeping flow control limits into account. Data that cannot be sent as 0-rtt will be stored
     * for sending in 1-rtt packets (see writeRemaining).
     * @param earlyData
     * @param earlyDataSizeLeft
     */
    public void writeEarlyData(byte[] earlyData, boolean fin, long earlyDataSizeLeft) throws IOException {
        this.earlyData = earlyData;
        earlyDataIsFinalInStream = fin;
        long flowControlLimit = flowController.getFlowControlLimit(this);
        int earlyDataLength = (int) Long.min(earlyData.length, Long.min(earlyDataSizeLeft, flowControlLimit));
        if (earlyDataLength > 0) {
            log.info(String.format("Sending %d bytes of early data on %s", earlyDataLength, this));
        }
        else {
            log.error("Sending no early data because: fc limit is " + flowControlLimit + "; early data size left is " + earlyDataSizeLeft + " and early data length is " + earlyData.length);
        }

        getOutputStream().write(earlyData, 0, earlyDataLength);
        if (earlyDataLength == earlyData.length && earlyDataIsFinalInStream) {
            getOutputStream().close();
        }
        sendingEarlyData = false;
        remainingData = Arrays.copyOfRange(earlyData, earlyDataLength, earlyData.length);
    }

    public void writeRemaining(boolean earlyDataWasAccepted) throws IOException {
        writingEarlyData = false;
        if (earlyDataWasAccepted) {
            if (remainingData.length > 0) {
                getOutputStream().write(remainingData);
                getOutputStream().close();
            }
            else {
                earlyDataSent = true;  // Order important: set earlyDataSent before testing finalFrameSent
                if (finalFrameSent) {
                    stopFlowControl();
                }
            }
        }
        else {
            // TODO reconsider creating new QuicStream object, or fix resetOutputStream to make it thread safe.
            // Also consider to pass encryption level in that constructor to get rit of getEncryptionLevel
            resetOutputStream();
            getOutputStream().write(earlyData);
            earlyDataSent = true;
            if (earlyDataIsFinalInStream) {
                getOutputStream().close();
            }
        }
    }

    @Override
    protected StreamOutputStream createStreamOutputStream(Integer sendBufferSize, FlowControl flowControl) {
        return new EarlyDataStreamOutputStreamImpl(sendBufferSize, flowControl);
    }

    protected class EarlyDataStreamOutputStreamImpl extends StreamOutputStreamImpl {
        protected EarlyDataStreamOutputStreamImpl(Integer sendBufferSize, FlowControl flowController) {
            super(EarlyDataStream.this, sendBufferSize, flowController, log);
        }

        @Override
        protected EncryptionLevel getEncryptionLevel() {
            return writingEarlyData? EncryptionLevel.ZeroRTT: EncryptionLevel.App;
        }

        @Override
        protected void finalFrameSent() {
            finalFrameSent = true;
            if (earlyDataSent) {
                stopFlowControl();
            }
        }
    }
}

