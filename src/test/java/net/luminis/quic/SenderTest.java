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

import net.luminis.quic.frame.*;
import net.luminis.quic.log.Logger;
import net.luminis.quic.log.SysOutLogger;
import net.luminis.quic.recovery.RecoveryManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.internal.util.reflection.FieldReader;
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
    private QuicConnectionImpl connection;

    // Arbitrary Instant value, used by tests to indicate the value does not matter for the test
    private Instant whenever = Instant.now();

    @BeforeAll
    static void initLogger() {
        logger = new SysOutLogger();
        logger.logDebug(true);
        logger.logCongestionControl(true);
        logger.logRecovery(true);
    }

    @BeforeEach
    void initSenderUnderTest() throws Exception {
        socket = mock(DatagramSocket.class);
        Logger logger = mock(Logger.class);
        connection = mock(QuicConnectionImpl.class);
        sender = new Sender(socket, 1500, logger, InetAddress.getLoopbackAddress(), 443, connection, null);

        // Set RttEstimator with short initial rtt, both on Sender and RecoveryManager
        RttEstimator rttEstimator = new RttEstimator(logger, 100);
        FieldSetter.setField(sender, sender.getClass().getDeclaredField("rttEstimater"), rttEstimator);
        RecoveryManager recoveryManager = (RecoveryManager) new FieldReader(sender, sender.getClass().getDeclaredField("recoveryManager")).read();
        FieldSetter.setField(recoveryManager, recoveryManager.getClass().getDeclaredField("rttEstimater"), rttEstimator);
    }

    @AfterEach
    void stopRecovery() {
        sender.stop();
    }
    @Test
    void testSingleSend() throws Exception {
        setCongestionWindowSize(1250);
        sender.start(mock(ConnectionSecrets.class));
        sender.send(new MockPacket(0, 1240, "packet 1"), "packet 1", p -> {});
        waitForSender();

        verify(socket, times(1)).send(any(DatagramPacket.class));
    }

    @Test
    void testSenderIsCongestionControlled() throws Exception {
        setCongestionWindowSize(1250);
        sender.start(mock(ConnectionSecrets.class));
        sender.send(new MockPacket(0, 1240, "packet 1"), "packet 1", p -> {});
        sender.send(new MockPacket(1, 1240, "packet 2"), "packet 2", p -> {});

        waitForSender();
        // Because of congestion control, only first packet should have been sent.
        verify(socket, times(1)).send(any(DatagramPacket.class));

        // An ack on first packet
        sender.process(new AckFrame(Version.getDefault(), 0), PnSpace.App, Instant.now());

        waitForSender();
        // Because congestion window is decreased, second packet should now have been sent too.
        verify(socket, times(2)).send(any(DatagramPacket.class));
    }

    @Test
    void testSenderCongestionControlWithUnrelatedAck() throws Exception {
        setCongestionWindowSize(1250);
        sender.start(mock(ConnectionSecrets.class));

        sender.send(new MockPacket(0, 12, EncryptionLevel.Initial, new PingFrame(), "initial"), "packet 1", p -> {});
        sender.send(new MockPacket(0, 1230, "packet 1"), "packet 1", p -> {});
        sender.send(new MockPacket(1, 1230, "packet 2"), "packet 2", p -> {});

        waitForSender();
        // Because of congestion control, only first 2 packets should have been sent.
        verify(socket, times(2)).send(any(DatagramPacket.class));

        // An ack on first packet should not decrease the congestion window too much (i.e. only with 12), so CC will still block sending the third packet
        sender.process(new AckFrame(0), PnSpace.Initial, Instant.now());

        waitForSender();
        verify(socket, times(2)).send(any(DatagramPacket.class));
    }

    @Test
    void testSenderCongestionControlWithIncorrectAck() throws Exception {
        disableRecoveryManager();
        setCongestionWindowSize(1250);
        sender.start(mock(ConnectionSecrets.class));

        sender.send(new MockPacket(0, 1240, EncryptionLevel.App, new PingFrame(), "packet 1"), "packet 1", p -> {});
        sender.send(new MockPacket(1, 1240, EncryptionLevel.App, new PingFrame(), "packet 2"), "packet 2", p -> {});

        waitForSender();
        // Because of congestion control, only first packet should have been sent.
        verify(socket, times(1)).send(any(DatagramPacket.class));

        // An ack on a non-existent packet, shouldn't change anything.
        sender.process(new AckFrame(0), PnSpace.Handshake, null);

        waitForSender();
        verify(socket, times(1)).send(any(DatagramPacket.class));
    }

    @Test
    void ackElicitingPacketsShouldBeRetransmitted() throws Exception {
        when(connection.createPacket(any(EncryptionLevel.class), any(QuicFrame.class))).thenAnswer(invocation -> new MockPacket(11, 12, EncryptionLevel.App, new PingFrame(), "ping packet"));
        sender.start(mock(ConnectionSecrets.class));

        sender.send(new MockPacket(0, 1240, EncryptionLevel.App, new PingFrame(), "packet 1"), "packet 1", p -> { /* retransmit function not needed, probe will be send */ });
        waitForSender();
        verify(socket, times(1)).send(argThat(new PacketMatcher(0, EncryptionLevel.App)));
        clearInvocations(socket);

        Thread.sleep(300);
        verify(socket, atLeast(1)).send(any(DatagramPacket.class));  // At least one probe will be sent, maybe multiple
    }

    @Test
    void ackOnlyPacketsShouldNotBeRetransmitted() throws Exception {
        when(connection.createPacket(any(EncryptionLevel.class), any(QuicFrame.class))).thenAnswer(invocation -> new MockPacket(11, 12, EncryptionLevel.App, new PingFrame(), "ping packet"));
        sender.start(mock(ConnectionSecrets.class));

        // Simulate a roundtrip first, to ensure loss detector has at least one ack-eliciting packet
        sender.send(new MockPacket(0, 120, EncryptionLevel.App, new PingFrame(), "packet 0"), "packet 0", p -> {});
        waitForSender();
        sender.process(new AckFrame(0), PnSpace.App, Instant.now());
        clearInvocations(socket);

        sender.send(new MockPacket(1, 1240, EncryptionLevel.App, new AckFrame(0), "packet 1"), "packet 1", p -> { /* retransmit function not needed, probe would be send */ });
        waitForSender();
        verify(socket, times(1)).send(argThat(new PacketMatcher(1, EncryptionLevel.App)));
        clearInvocations(socket);

        Thread.sleep(500);
        verify(socket, never()).send(any(DatagramPacket.class));
    }

    @Test
    void receivingPacketLeadsToSendAckPacket() throws IOException  {
        sender.start(mock(ConnectionSecrets.class));
        when(connection.createPacket(any(EncryptionLevel.class), any(QuicFrame.class)))
                .thenReturn(new MockPacket(0, 10, EncryptionLevel.Initial));

        sender.processPacketReceived(new MockPacket(0, 1000, EncryptionLevel.Initial, new CryptoFrame()));
        sender.packetProcessed(EncryptionLevel.Initial);

        waitForSender();

        verify(socket, times(1)).send(any(DatagramPacket.class));  // TODO: would be nice to check send packet actually contains an ack frame...
    }

    @Test
    void receivingAckOnlyPacketShouldNotLeadToSendingAckPacket() throws IOException  {
        sender.start(mock(ConnectionSecrets.class));
        when(connection.createPacket(any(EncryptionLevel.class), any(QuicFrame.class)))
                .thenReturn(new MockPacket(0, 10, EncryptionLevel.Initial));

        sender.processPacketReceived(new MockPacket(0, 1000, EncryptionLevel.Initial, new AckFrame(0)));
        sender.packetProcessed(EncryptionLevel.Initial);

        waitForSender();

        verify(socket, never()).send(any(DatagramPacket.class));
    }

    @Test
    void whenWaitForCongestionControllerIsInteruptedBecauseOfProcessedPacketWaitingPacketShouldRemainWaiting() throws Exception {
        disableRecoveryManager();
        setCongestionWindowSize(1212);
        sender.start(mock(ConnectionSecrets.class));

        // Send first packet to fill up cwnd
        MockPacket firstPacket = new MockPacket(0, 1200, EncryptionLevel.App, new PingFrame(), "first packet");
        sender.send(firstPacket, "first packet", p -> {});
        waitForSender();
        verify(socket, times(1)).send(argThat(matchesPacket(0, EncryptionLevel.App)));
        clearInvocations(socket);

        // Send second packet and third packet, which will both be queued because of cwnd
        sender.send(new MockPacket(1, 1200, EncryptionLevel.App, new PingFrame(), "large packet"), "large packet", p -> {});
        waitForSender();
        sender.send(new MockPacket(2, 120, EncryptionLevel.App, new PingFrame(), "third packet"), "third packet", p -> {});
        waitForSender();
        clearInvocations(socket);

        // Simulate incoming packet; sender will be interrupted because maybe an ack must be sent.
        sender.packetProcessed(EncryptionLevel.App);

        waitForSender();

        verify(socket, never()).send(any(DatagramPacket.class));
    }

    @Test
    void whenCwndAlmostReachedProbeShouldNotBeBlocked() throws Exception {
        disableRecoveryManager();

        when(connection.createPacket(any(EncryptionLevel.class), any(QuicFrame.class))).thenAnswer(invocation -> new MockPacket(1, 12, EncryptionLevel.App, new PingFrame(), "ping packet"));
        setCongestionWindowSize(1202);
        sender.start(mock(ConnectionSecrets.class));

        // Send first packet to fill up cwnd
        MockPacket firstPacket = new MockPacket(0, 1200, EncryptionLevel.App, new Padding(), "first packet");
        sender.send(firstPacket, "first packet", p -> {});
        waitForSender();
        verify(socket, times(1)).send(argThat(matchesPacket(0, EncryptionLevel.App)));
        clearInvocations(socket);

        sender.sendProbe();
        waitForSender();

        verify(socket, times(1)).send(argThat(matchesPacket(1, EncryptionLevel.App)));
    }

    @Test
    void whenCongestionControllerIsBlockingProbeShouldNotBeBlocked() throws Exception {
        disableRecoveryManager();

        when(connection.createPacket(any(EncryptionLevel.class), any(QuicFrame.class))).thenAnswer(invocation -> new MockPacket(2, 12, EncryptionLevel.App, new PingFrame(), "ping packet"));
        setCongestionWindowSize(1212);
        sender.start(mock(ConnectionSecrets.class));

        // Send first packet to fill up cwnd
        MockPacket firstPacket = new MockPacket(0, 1200, EncryptionLevel.App, new Padding(), "first packet");
        sender.send(firstPacket, "first packet", p -> {});
        waitForSender();
        verify(socket, times(1)).send(argThat(matchesPacket(0, EncryptionLevel.App)));
        reset(socket);

        // Send second packet to exceed cwnd (and make sender wait)
        MockPacket secondPacket = new MockPacket(1, 1200, EncryptionLevel.App, new Padding(), "second packet");
        sender.send(firstPacket, "second packet", p -> {});
        waitForSender();
        verify(socket, never()).send(any(DatagramPacket.class));
        reset(socket);

        sender.sendProbe();
        waitForSender();

        // Whether a special probe or waiting data is sent does not matter, as long as a packet is sent.
        verify(socket, times(1)).send(any(DatagramPacket.class));
    }

    @Test
    void ackOnlyShouldNotBeCongestionControlled() throws Exception {
        setCongestionWindowSize(1212);
        sender.start(mock(ConnectionSecrets.class));
        when(connection.createPacket(any(EncryptionLevel.class), any(QuicFrame.class))).thenAnswer(invocation -> new MockPacket(-11, 12, EncryptionLevel.App, new PingFrame(), "empty packet"));

        // Send first packet to fill up cwnd
        MockPacket firstPacket = new MockPacket(0, 1210, EncryptionLevel.App, new PingFrame(), "first packet");
        sender.send(firstPacket, "first packet", p -> {});
        waitForSender();
        verify(socket, times(1)).send(argThat(matchesPacket(0, EncryptionLevel.App)));
        clearInvocations(socket);

        sender.processPacketReceived(new MockPacket(19, 200, EncryptionLevel.App, new MaxDataFrame(1_000_000), "stream frame"));
        sender.packetProcessed(EncryptionLevel.App);
        waitForSender();

        verify(socket, times(1)).send(argThat(matchesPacket(1, EncryptionLevel.App)));
    }

    @Test
    void ackOnlyShouldNotBeCountedAsInFlight() throws Exception {
        disableRecoveryManager();
        sender.start(mock(ConnectionSecrets.class));
        when(connection.createPacket(any(EncryptionLevel.class), any(QuicFrame.class))).thenAnswer(invocation -> new MockPacket(-1, 12, EncryptionLevel.App, "empty packet"));

        sender.processPacketReceived(new MockPacket(19, 200, EncryptionLevel.App, new MaxDataFrame(1_000_000), "stream frame"));
        sender.packetProcessed(EncryptionLevel.App);
        waitForSender();

        verify(socket, times(1)).send(argThat(matchesPacket(0, EncryptionLevel.App)));
        assertThat(sender.getCongestionController().getBytesInFlight()).isEqualTo(0);
    }


    private PacketMatcher matchesPacket(int packetNumber, EncryptionLevel encryptionLevel ) {
        return new PacketMatcher(packetNumber, encryptionLevel);
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
        FieldSetter.setField(congestionController, congestionController.getClass().getSuperclass().getDeclaredField("congestionWindow"), cwnd);
    }

    private void disableRecoveryManager() throws Exception {
        RecoveryManager recoveryManager = mock(RecoveryManager.class);
        FieldSetter.setField(sender, sender.getClass().getDeclaredField("recoveryManager"), recoveryManager);
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