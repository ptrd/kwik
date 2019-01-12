package net.luminis.quic;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

import static org.mockito.Mockito.*;

class SenderTest {

    private static Logger logger;

    @BeforeAll
    static void initLogger() {
        logger = new Logger();
        logger.logDebug(true);
    }

    @Test
    void testSingleSend() throws IOException {
        DatagramSocket socket = mock(DatagramSocket.class);
        Logger logger = mock(Logger.class);
        Sender sender = new Sender(socket, 1500, logger, InetAddress.getLoopbackAddress(), 443);
        sender.start();

        sender.send(new MockPacket(0, 1240, "packet 1"), "packet 1");
        waitForSender();

        verify(socket, times(1)).send(any(DatagramPacket.class));
    }

    @Test
    void testSenderIsCongestionControlled() throws IOException {
        DatagramSocket socket = mock(DatagramSocket.class);
        Sender sender = new Sender(socket, 1500, logger, InetAddress.getLoopbackAddress(), 443);
        sender.start();

        sender.send(new MockPacket(0, 1240, "packet 1"), "packet 1");
        sender.send(new MockPacket(1, 1240, "packet 2"), "packet 2");

        waitForSender();
        // Because of congestion control, only first packet should have been sent.
        verify(socket, times(1)).send(any(DatagramPacket.class));

        // An ack on first packet
        sender.process(new AckFrame(Version.getDefault(), 0), EncryptionLevel.App);

        waitForSender();
        // Because congestion window is decreased, second packet should now have been sent too.
        verify(socket, times(2)).send(any(DatagramPacket.class));
    }

    @Test
    void testSenderCongestionControlWithUnrelatedAck() throws IOException {
        DatagramSocket socket = mock(DatagramSocket.class);
        Sender sender = new Sender(socket, 1500, logger, InetAddress.getLoopbackAddress(), 443);
        sender.start();

        sender.send(new MockPacket(0, 1, EncryptionLevel.Initial,"initial"), "packet 1");
        sender.send(new MockPacket(0, 1240, "packet 1"), "packet 1");
        sender.send(new MockPacket(1, 1240, "packet 2"), "packet 2");

        waitForSender();
        // Because of congestion control, only first 2 packets should have been sent.
        verify(socket, times(2)).send(any(DatagramPacket.class));

        // An ack on initial packet should not decrease the congestion window too much
        sender.process(new AckFrame(Version.getDefault(), 0), EncryptionLevel.Initial);

        waitForSender();
        verify(socket, times(2)).send(any(DatagramPacket.class));
    }

    @Test
    void testSenderCongestionControlWithIncorrectAck() throws IOException {
        DatagramSocket socket = mock(DatagramSocket.class);
        Sender sender = new Sender(socket, 1500, logger, InetAddress.getLoopbackAddress(), 443);
        sender.start();

        sender.send(new MockPacket(0, 1240, "packet 1"), "packet 1");
        sender.send(new MockPacket(1, 1240, "packet 2"), "packet 2");

        waitForSender();
        // Because of congestion control, only first packet should have been sent.
        verify(socket, times(1)).send(any(DatagramPacket.class));

        // An ack on a non-existant packet, shouldn't change anything.
        sender.process(new AckFrame(Version.getDefault(), 0), EncryptionLevel.Handshake);

        waitForSender();
        verify(socket, times(1)).send(any(DatagramPacket.class));
    }


    private void waitForSender() {
        // Because sender is asynchronous, test must wait a little to give sender thread a change to execute.
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}