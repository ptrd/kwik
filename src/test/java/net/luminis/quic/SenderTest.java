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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.internal.util.reflection.FieldSetter;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class SenderTest {

    private static Logger logger;
    private Sender sender;
    private DatagramSocket socket;
    private QuicConnection connection;

    @BeforeAll
    static void initLogger() {
        logger = new SysOutLogger();
        logger.logDebug(true);
    }

    @BeforeEach
    void initSenderUnderTest() throws Exception {
        socket = mock(DatagramSocket.class);
        Logger logger = mock(Logger.class);
        sender = new Sender(socket, 1500, logger, InetAddress.getLoopbackAddress(), 443, connection);
        FieldSetter.setField(sender, sender.getClass().getDeclaredField("rttEstimater"), new RttEstimator(logger, 100));
        connection = mock(QuicConnection.class);
        FieldSetter.setField(sender, sender.getClass().getDeclaredField("connection"), connection);
    }

    @Test
    void testSingleSend() throws Exception {
        setCongestionWindowSize(1250);
        sender.start(null);
        sender.send(new MockPacket(0, 1240, "packet 1"), "packet 1", p -> {});
        waitForSender();

        verify(socket, times(1)).send(any(DatagramPacket.class));
    }

    @Test
    void testSenderIsCongestionControlled() throws Exception {
        setCongestionWindowSize(1250);
        sender.start(null);
        sender.send(new MockPacket(0, 1240, "packet 1"), "packet 1", p -> {});
        sender.send(new MockPacket(1, 1240, "packet 2"), "packet 2", p -> {});

        waitForSender();
        // Because of congestion control, only first packet should have been sent.
        verify(socket, times(1)).send(any(DatagramPacket.class));

        // An ack on first packet
        sender.process(new AckFrame(Version.getDefault(), 0), EncryptionLevel.App, Instant.now());

        waitForSender();
        // Because congestion window is decreased, second packet should now have been sent too.
        verify(socket, times(2)).send(any(DatagramPacket.class));
    }

    @Test
    void testSenderCongestionControlWithUnrelatedAck() throws Exception {
        setCongestionWindowSize(1250);
        sender.start(null);

        sender.send(new MockPacket(0, 12, EncryptionLevel.Initial,"initial"), "packet 1", p -> {});
        sender.send(new MockPacket(0, 1230, "packet 1"), "packet 1", p -> {});
        sender.send(new MockPacket(1, 1230, "packet 2"), "packet 2", p -> {});

        waitForSender();
        // Because of congestion control, only first 2 packets should have been sent.
        verify(socket, times(2)).send(any(DatagramPacket.class));

        // An ack on initial packet should not decrease the congestion window too much
        sender.process(new AckFrame(Version.getDefault(), 0), EncryptionLevel.Initial, Instant.now());

        waitForSender();
        verify(socket, times(2)).send(any(DatagramPacket.class));
    }

    @Test
    void testSenderCongestionControlWithIncorrectAck() throws Exception {
        setCongestionWindowSize(1250);
        sender.start(null);

        sender.send(new MockPacket(0, 1240, "packet 1"), "packet 1", p -> {});
        sender.send(new MockPacket(1, 1240, "packet 2"), "packet 2", p -> {});

        waitForSender();
        // Because of congestion control, only first packet should have been sent.
        verify(socket, times(1)).send(any(DatagramPacket.class));

        // An ack on a non-existant packet, shouldn't change anything.
        sender.process(new AckFrame(Version.getDefault(), 0), EncryptionLevel.Handshake, null);

        waitForSender();
        verify(socket, times(1)).send(any(DatagramPacket.class));
    }

    @Test
    void ackOnlyPacketsShouldNotBeRetransmitted() throws Exception {
        sender.start(null);

        sender.send(new MockPacket(0, 1240, EncryptionLevel.Initial, new AckFrame(), "packet 1"), "packet 1", p -> {});
        waitForSender();
        verify(socket, times(1)).send(argThat(new PacketMatcher(0, EncryptionLevel.Initial)));
        clearInvocations(socket);

        try {
            Thread.sleep(300);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    @Test
    void receivingPacketLeadsToSendAckPacket() throws IOException  {
        sender.start(null);
        when(connection.createPacket(any(EncryptionLevel.class), any(QuicFrame.class)))
                .thenReturn(new MockPacket(0, 10, EncryptionLevel.Initial));

        sender.processPacketReceived(new MockPacket(0, 1000, EncryptionLevel.Initial, new CryptoFrame()));
        sender.packetProcessed(EncryptionLevel.Initial);

        waitForSender();

        verify(socket, times(1)).send(any(DatagramPacket.class));  // TODO: would be nice to check send packet actually contains an ack frame...
    }

    @Test
    void receivingVersionNegotationPacke() throws IOException {
        sender.processPacketReceived(new VersionNegotationPacket());

        waitForSender();

        verify(socket, never()).send(any(DatagramPacket.class));
    }

    @Test
    void whenWaitForCongestionControllerIsInteruptedBecauseOfProcessedPacketWaitingPacketShouldRemainWaiting() throws Exception {
        setCongestionWindowSize(1212);
        sender.start(null);

        // Send first packet to fill up cwnd
        MockPacket firstPacket = new MockPacket(0, 1200, EncryptionLevel.App, new AckFrame(), "first packet");
        sender.send(firstPacket, "first packet", p -> {});
        waitForSender();
        verify(socket, times(1)).send(argThat(matchesPacket(0, EncryptionLevel.App)));
        reset(socket);

        // Send second packet and third packet, which will both be queued because of cwnd
        sender.send(new MockPacket(1, 1200, EncryptionLevel.App, new AckFrame(), "large packet"), "large packet", p -> {});
        waitForSender();
        sender.send(new MockPacket(2, 120, EncryptionLevel.App, new AckFrame(), "third packet"), "third packet", p -> {});
        waitForSender();

        // Simulate incoming packet; sender will be interrupted because maybe an ack must be sent.
        sender.packetProcessed(EncryptionLevel.App);

        // Now, increase cwnd.
        sender.getCongestionController().registerAcked(new PacketInfo(null, firstPacket, null));
        waitForSender();
        // The first waiting packet should be sent.
        verify(socket, times(1)).send(argThat(matchesPacket(1, EncryptionLevel.App)));
    }


    private PacketMatcher matchesPacket(int packetNumber, EncryptionLevel encryptionLevel ) {
        return new PacketMatcher(packetNumber, encryptionLevel);
    }

    void receivingRetryPacket() throws IOException {
        sender.processPacketReceived(new RetryPacket(Version.getDefault()));

        waitForSender();

        verify(socket, never()).send(any(DatagramPacket.class));
    }

    private void waitForSender() {
        // Because sender is asynchronous, test must wait a little to give sender thread a change to execute.
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    private void setCongestionWindowSize(int cwnd) throws Exception {
        CongestionController congestionController = sender.getCongestionController();
        FieldSetter.setField(congestionController, congestionController.getClass().getDeclaredField("congestionWindow"), cwnd);
    }

    static class PacketMatcher implements ArgumentMatcher<DatagramPacket> {
        private final long packetNumber;
        private final EncryptionLevel encryptionLevel;

        public PacketMatcher(int packetNumber, EncryptionLevel encryptionLevel) {
            this.packetNumber = packetNumber;
            this.encryptionLevel = encryptionLevel;
        }

        @Override
        public boolean matches(DatagramPacket datagramPacket) {
            ByteBuffer buffer = ByteBuffer.wrap(datagramPacket.getData());
            long sentPn = buffer.getLong();
            int sentLevel = buffer.getInt();
            return sentPn == packetNumber && sentLevel == encryptionLevel.ordinal();
        }
    }
}