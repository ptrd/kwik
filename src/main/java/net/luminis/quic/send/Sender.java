/*
 * Copyright © 2020, 2021, 2022 Peter Doornbosch
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
package net.luminis.quic.send;

import net.luminis.quic.EncryptionLevel;
import net.luminis.quic.PnSpace;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.packet.QuicPacket;

import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * This interface defines methods for sending QUIC frames or packets to a given peer. When sending frames, the implementation
 * takes care of packaging frames into appropriate packets, taking into account limitations imposed by congestion control and
 * send priorities.
 *
 * The send methods will (almost) never lead to a synchronous send; instead, the sender implementation will queue the
 * send requests and actually send them when appropriate (what is "appropriate" is defined by the sender implementation).
 *
 * The notification methods <code>packetProcessed</code> and <code>datagramProcessed</code> should be used to notify
 * the sender implementation of these events, which enables the sender to coalesce packets efficiently.
 * For cases where sending is not triggered by processing a packet and these methods are not called, the caller must
 * call <code>flush</code> instead, to trigger the sender implementation to start packaging.
 */
public interface Sender {

    Consumer<QuicFrame> NO_RETRANSMIT = f -> {};

    /**
     * Sends a (fixed) frame. Should not be used to send data that is subject to change (e.g. a flow control level),
     * as the frame might stay queued for some time when conditions are bad.
     * The given frame will only be transmitted once; this method does not provide retransmission.
     * @param frame
     * @param level
     */
    void send(QuicFrame frame, EncryptionLevel level);

    /**
     * Sends a (fixed) frame. Should not be used to send data that is subject to change (e.g. a flow control level),
     * as the frame might stay queued for some time when conditions are bad.
     * When packet used to send the frame is lost, the callback will be executed to give the caller the opportunity
     * to retransmit.
     * @param frame
     * @param level
     * @param frameLostCallback
     */
    void send(QuicFrame frame, EncryptionLevel level, Consumer<QuicFrame> frameLostCallback);

    /**
     * Sends a frame that is produced by the given frame supplier at the time the frame is actually being sent.
     * Producing the frame "just in time" has two advantages: the frame can be created with up-to-date data (e.g.
     * flow control level), avoid sending out-of-date values when the send-request has been queued for a while, and the
     * frame can take the maximum size that is available in the QUIC packet being constructed (which is especially
     * useful for stream frames).
     *
     * The mininum size is the minimal maximum frame size the frame supplier callback is able to produce; it must
     * guarantee that it can produce a frame that is not larger than this value. For fixed frames, this is simply the
     * max frame size, but for frames with varying size (e.g. stream frames), it is the max size when creating the
     * smallest frame possible (or useful) in the given circumstances. E.g. if frame size is uncertain due
     * to variable length integer encoding, this minimum should take worst case into account.
     * Note that when the frame supplier is called, it may be allowed to produce a larger frame, if packet size permits.
     *
     * When packet used to send the frame is lost, the callback will be executed to give the caller the opportunity
     * to retransmit.
     *
     * @param frameSupplier    function that provides the frame that is being send, the integer input parameter is the
     *                         maximum size the frame may have
     * @param minimumSize      the minimum size the frame supplier function can produce
     * @param level
     * @param lostCallback
     */
    void send(Function<Integer, QuicFrame> frameSupplier, int minimumSize, EncryptionLevel level, Consumer<QuicFrame> lostCallback);

    /**
     * Set the initial token that should be used for all initial packets.
     * @param token
     */
    void setInitialToken(byte[] token);

    /**
     * Ensures an Ack is sent within the given time.
     * @param maxDelay
     */
    void sendAck(PnSpace pnSpace, int maxDelay);

    /**
     * Sends an empty probe.
     * @param level
     */
    void sendProbe(EncryptionLevel level);

    /**
     * Sends a probe with the given frames.
     * @param frames
     * @param level
     */
    void sendProbe(List<QuicFrame> frames, EncryptionLevel level);

    /**
     * Notifies the sender that a packet is completely processed.
     * @param expectingMore
     */
    void packetProcessed(boolean expectingMore);

    /**
     * Notifies the sender that a datagram (which may contain multiple packets) is completely processed.
     * @param expectingMore
     */
    void datagramProcessed(boolean expectingMore);

    /**
     * Notifies the sender that queued frames and packets should be sent as soon as possible.
     */
    void flush();
}
