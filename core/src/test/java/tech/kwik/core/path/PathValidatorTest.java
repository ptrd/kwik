/*
 * Copyright © 2025 Peter Doornbosch
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
package tech.kwik.core.path;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import tech.kwik.core.frame.*;
import tech.kwik.core.impl.Version;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.packet.ShortHeaderPacket;
import tech.kwik.core.send.SenderImpl;
import tech.kwik.core.socket.ServerConnectionSocketManager;
import tech.kwik.core.test.TestClock;
import tech.kwik.core.test.TestScheduledExecutor;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

class PathValidatorTest {


    private PathValidator pathValidator;
    private InetSocketAddress defaultClientAddress;
    private SenderImpl sender;
    private ServerConnectionSocketManager socketManager;
    private TestClock testClock;
    private TestScheduledExecutor testScheduledExecutor;

    //region setup
    @BeforeEach
    void setup() {
        defaultClientAddress = new InetSocketAddress("localhost", 43861);
        sender = mock(SenderImpl.class);
        socketManager = mock(ServerConnectionSocketManager.class);
        testClock = new TestClock();
        testScheduledExecutor = new TestScheduledExecutor(testClock);
        pathValidator = new PathValidator(testScheduledExecutor, VersionHolder.with(Version.getDefault()), defaultClientAddress, sender, mock(Logger.class), socketManager, testClock);
    }

    @AfterEach
    void tearDown() {
        testScheduledExecutor.shutdown();
    }
    //endregion

    //region initiate path validation
    @Test
    void whenPacketWithDifferentClientAddressIsReceivedPathChallengeIsSent() {
        // Given
        PacketMetaData packetMetaData = metaDataFor(1200, new InetSocketAddress("localhost", 59643));

        // When
        pathValidator.checkSourceAddress(normalPacket(), packetMetaData);

        // Then
        verify(sender).sendAlternateAddress(any(PathChallengeFrame.class), argThat(address -> ! address.equals(defaultClientAddress)));
    }

    @Test
    void whenPacketWithDifferentClientAddressIsReceivedPathChallengePacketIsNotLargerThenAmplificationLimit() {
        // Given
        int pingPacketSize = 18 + 8 + 3;
        PacketMetaData packetMetaData = metaDataFor(pingPacketSize, new InetSocketAddress("localhost", 59643));

        // When
        pathValidator.checkSourceAddress(normalPacket(), packetMetaData);

        // Then
        int antiAmplificationLimit = 3 * pingPacketSize;
        int maxPayloadSize = antiAmplificationLimit - (18 + 8);  // short packet overhead + dcid size
        verify(sender).sendAlternateAddress(argThat(frame -> frame.getFrameLength() <= maxPayloadSize), any(InetSocketAddress.class));
    }

    @Test
    void whenPathValidationInProgressDoNotRespondToChangedClientAddressWithPathChallenge() {
        // Given
        PacketMetaData packetMetaData = metaDataFor(1200, new InetSocketAddress("localhost", 59643));
        pathValidator.checkSourceAddress(normalPacket(), packetMetaData);
        clearInvocations(sender);

        // When
        pathValidator.checkSourceAddress(normalPacket(), packetMetaData);

        // Then
        verify(sender, never()).sendAlternateAddress(any(PathChallengeFrame.class), any(InetSocketAddress.class));
    }
    //endregion

    //region validate path
    @Test
    void whenMatchingPathResponseIsReceivedPathIsValidated() {
        // Given
        InetSocketAddress newAddress = new InetSocketAddress("localhost", 59643);
        PacketMetaData packetMetaData = metaDataFor(1200, newAddress);
        pathValidator.checkSourceAddress(normalPacket(), packetMetaData);
        PathChallengeFrame pathChallengeFrame = capturePathChallengeFrame();

        // When
        PathResponseFrame pathResponseFrame = new PathResponseFrame(Version.getDefault(), pathChallengeFrame.getData());
        pathValidator.checkPathResponse(pathResponseFrame, metaDataFor(1200, newAddress));

        // Then
        assertThat(pathValidator.isValidated(newAddress)).isTrue();
    }

    @Test
    void whenMatchingPathResponseIsReceivedOnDifferentPathPathIsValidated() {
        // Given
        InetSocketAddress challengeAddress = new InetSocketAddress("localhost", 59643);
        PacketMetaData packetMetaData = metaDataFor(1200, challengeAddress);
        pathValidator.checkSourceAddress(normalPacket(), packetMetaData);
        PathChallengeFrame pathChallengeFrame = capturePathChallengeFrame();

        // When
        InetSocketAddress responseAddress = new InetSocketAddress("localhost", 34684);
        PathResponseFrame pathResponseFrame = new PathResponseFrame(Version.getDefault(), pathChallengeFrame.getData());
        pathValidator.checkPathResponse(pathResponseFrame, metaDataFor(1200, responseAddress));

        // Then
        assertThat(pathValidator.isValidated(challengeAddress)).isTrue();
    }

    @Test
    void whenNonMatchingPathResponseIsReceivedPathIsNotValidated() {
        // Given
        InetSocketAddress newAddress = new InetSocketAddress("localhost", 59643);
        PacketMetaData packetMetaData = metaDataFor(1200, newAddress);
        pathValidator.checkSourceAddress(normalPacket(), packetMetaData);

        // When
        byte[] falseResponseData = new byte[8];
        PathResponseFrame pathResponseFrame = new PathResponseFrame(Version.getDefault(), falseResponseData);
        pathValidator.checkPathResponse(pathResponseFrame, metaDataFor(1200, newAddress));

        // Then
        assertThat(pathValidator.isValidated(newAddress)).isFalse();
    }

    @Test
    void whenOtherFramesAreReceivedPathIsNotValidated() {
        // Given
        InetSocketAddress newAddress = new InetSocketAddress("localhost", 59643);
        PacketMetaData packetMetaData = metaDataFor(1200, newAddress);
        pathValidator.checkSourceAddress(normalPacket(), packetMetaData);

        // When
        pathValidator.checkSourceAddress(normalPacket(), packetMetaData);

        // Then
        assertThat(pathValidator.isValidated(newAddress)).isFalse();
    }
    //endregion

    //region path validation timeout
    @Test
    void whenNoPathResponseIsReceivedNewPathChallengeIsSent() {
        // Given
        PacketMetaData packetMetaData = metaDataFor(1200, new InetSocketAddress("localhost", 59643));
        pathValidator.checkSourceAddress(normalPacket(), packetMetaData);
        clearInvocations(sender);
        int initalPto = 1000;

        // When
        testClock.fastForward(initalPto);

        // Then
        verify(sender).sendAlternateAddress(any(PathChallengeFrame.class), argThat(address -> ! address.equals(defaultClientAddress)));
    }

    @Test
    void whenNoPathResponseIsReceivedNewPathChallengesAreSent() {
        // Given
        PacketMetaData packetMetaData = metaDataFor(1200, new InetSocketAddress("localhost", 59643));
        pathValidator.checkSourceAddress(normalPacket(), packetMetaData);
        clearInvocations(sender);
        int initalPto = 1000;

        testClock.fastForward(initalPto);
        verify(sender).sendAlternateAddress(any(PathChallengeFrame.class), argThat(address -> ! address.equals(defaultClientAddress)));
        clearInvocations(sender);

        // When
        testClock.fastForward(initalPto);
        verify(sender, never()).sendAlternateAddress(any(PathChallengeFrame.class), any(InetSocketAddress.class));
        testClock.fastForward(initalPto);

        // Then
        verify(sender).sendAlternateAddress(any(PathChallengeFrame.class), argThat(address -> ! address.equals(defaultClientAddress)));
    }

    @Test
    void whenNoPathResponseIsReceivedAtAllValidationIsTerminated() {
        // Given
        PacketMetaData packetMetaData = metaDataFor(1200, new InetSocketAddress("localhost", 59643));
        pathValidator.checkSourceAddress(normalPacket(), packetMetaData);
        clearInvocations(sender);
        int initalPto = 1000;
        int timeout = 3 * initalPto;

        testClock.fastForward(timeout);
        clearInvocations(sender);

        // When
        testClock.fastForward(100 * initalPto);

        // Then
        verify(sender, never()).sendAlternateAddress(any(PathChallengeFrame.class), any(InetSocketAddress.class));
    }
    //endregion

    //region connection migration
    @Test
    void whenPathValidationWasStartedByNonProbingTheConnectionShouldBeMigratedAfterSuccessfullPathValidation() {
        // Given
        InetSocketAddress newAddress = new InetSocketAddress("localhost", 59643);
        PacketMetaData packetMetaData = metaDataFor(1200, newAddress);
        pathValidator.checkSourceAddress(normalPacket(), packetMetaData);
        PathChallengeFrame pathChallengeFrame = capturePathChallengeFrame();

        // When
        PathResponseFrame pathResponseFrame = new PathResponseFrame(Version.getDefault(), pathChallengeFrame.getData());
        pathValidator.checkPathResponse(pathResponseFrame, metaDataFor(1200, newAddress));

        // Then
        assertThat(pathValidator.isValidated(newAddress)).isTrue();
        verify(socketManager).changeClientAddress(argThat(address -> address.equals(newAddress)));
    }

    @Test
    void whenPathValidationWasStartedByProbingPacketTheConnectionShouldNotYetBeMigratedAfterSuccessfullPathValidation() {
        // Given
        InetSocketAddress newAddress = new InetSocketAddress("localhost", 59643);
        PacketMetaData packetMetaData = metaDataFor(1200, newAddress);
        QuicPacket probingPacket = new ShortHeaderPacket(68, new byte[8], new PathChallengeFrame(Version.getDefault(), new byte[8]));
        pathValidator.checkSourceAddress(probingPacket, packetMetaData);
        PathChallengeFrame pathChallengeFrame = capturePathChallengeFrame();

        // When
        PathResponseFrame pathResponseFrame = new PathResponseFrame(Version.getDefault(), pathChallengeFrame.getData());
        pathValidator.checkPathResponse(pathResponseFrame, metaDataFor(1200, newAddress));

        // Then
        assertThat(pathValidator.isValidated(newAddress)).isTrue();
        verify(socketManager, never()).changeClientAddress(any(InetSocketAddress.class));
    }

    @Test
    void whenPathIsValidatedNonProbingPacketShouldTriggerConnectionMigration() {
        // Given
        InetSocketAddress newAddress = new InetSocketAddress("localhost", 59643);
        PacketMetaData packetMetaData = metaDataFor(1200, newAddress);
        QuicPacket probingPacket = new ShortHeaderPacket(68, new byte[8], new PathChallengeFrame(Version.getDefault(), new byte[8]));
        pathValidator.checkSourceAddress(probingPacket, packetMetaData);
        PathChallengeFrame pathChallengeFrame = capturePathChallengeFrame();
        PathResponseFrame pathResponseFrame = new PathResponseFrame(Version.getDefault(), pathChallengeFrame.getData());
        pathValidator.checkPathResponse(pathResponseFrame, metaDataFor(1200, newAddress));
        verify(socketManager, never()).changeClientAddress(any(InetSocketAddress.class));
        assertThat(pathValidator.isValidated(newAddress)).isTrue();

        // When
        pathValidator.checkSourceAddress(normalPacket(), packetMetaData);

        // Then
        assertThat(pathValidator.isValidated(newAddress)).isTrue();
        verify(socketManager).changeClientAddress(argThat(address -> address.equals(newAddress)));
    }

    @Test
    void whenPathIsValidatedProbingPacketShouldNotTriggerConnectionMigration() {
        // Given
        InetSocketAddress newAddress = new InetSocketAddress("localhost", 59643);
        PacketMetaData packetMetaData = metaDataFor(1200, newAddress);
        QuicPacket probingPacket = new ShortHeaderPacket(68, new byte[8], new PathChallengeFrame(Version.getDefault(), new byte[8]));
        pathValidator.checkSourceAddress(probingPacket, packetMetaData);
        PathChallengeFrame pathChallengeFrame = capturePathChallengeFrame();
        PathResponseFrame pathResponseFrame = new PathResponseFrame(Version.getDefault(), pathChallengeFrame.getData());
        pathValidator.checkPathResponse(pathResponseFrame, metaDataFor(1200, newAddress));
        verify(socketManager, never()).changeClientAddress(any(InetSocketAddress.class));
        assertThat(pathValidator.isValidated(newAddress)).isTrue();

        // When
        QuicPacket anotherProbingPacket = new ShortHeaderPacket(69, new byte[8], new PathChallengeFrame(Version.getDefault(), new byte[8]));
        pathValidator.checkSourceAddress(anotherProbingPacket, packetMetaData);

        // Then
        assertThat(pathValidator.isValidated(newAddress)).isTrue();
        verify(socketManager, never()).changeClientAddress(argThat(address -> address.equals(newAddress)));
    }

    @Test
    void whenPathIsValidatedNonProbingPacketShouldNotTriggerConnectionMigrationWhenNotHighestNumbered() {
        // Given
        QuicPacket highestNumbered = new ShortHeaderPacket(80, new byte[8], new StreamFrame(1, new byte[571], false));
        pathValidator.checkSourceAddress(highestNumbered, metaDataFor(650, defaultClientAddress));

        InetSocketAddress newAddress = new InetSocketAddress("localhost", 59643);
        PacketMetaData packetMetaData = metaDataFor(1200, newAddress);
        QuicPacket probingPacket = new ShortHeaderPacket(78, new byte[8], new PathChallengeFrame(Version.getDefault(), new byte[8]));
        pathValidator.checkSourceAddress(probingPacket, packetMetaData);
        PathChallengeFrame pathChallengeFrame = capturePathChallengeFrame();
        PathResponseFrame pathResponseFrame = new PathResponseFrame(Version.getDefault(), pathChallengeFrame.getData());
        pathValidator.checkPathResponse(pathResponseFrame, metaDataFor(1200, newAddress));
        verify(socketManager, never()).changeClientAddress(any(InetSocketAddress.class));
        assertThat(pathValidator.isValidated(newAddress)).isTrue();

        // When
        QuicPacket newAddressPacket = normalPacket(79);
        pathValidator.checkSourceAddress(newAddressPacket, packetMetaData);

        // Then
        assertThat(pathValidator.isValidated(newAddress)).isTrue();
        verify(socketManager, never()).changeClientAddress(argThat(address -> address.equals(newAddress)));
    }

    @Test
    void whenClientMigratesBackToPreviousAddressServerShouldMigrateImmediately() {
        // Given
        InetSocketAddress newAddress = new InetSocketAddress("localhost", 59643);
        PacketMetaData packetMetaData = metaDataFor(1200, newAddress);
        pathValidator.checkSourceAddress(normalPacket(), packetMetaData);
        PathChallengeFrame pathChallengeFrame = capturePathChallengeFrame();
        PathResponseFrame pathResponseFrame = new PathResponseFrame(Version.getDefault(), pathChallengeFrame.getData());
        pathValidator.checkPathResponse(pathResponseFrame, metaDataFor(1200, newAddress));

        assertThat(pathValidator.isValidated(newAddress)).isTrue();
        verify(socketManager).changeClientAddress(argThat(address -> address.equals(newAddress)));
        clearInvocations(socketManager);

        // When
        pathValidator.checkSourceAddress(normalPacket(), metaDataFor(684, defaultClientAddress));

        // Then
        verify(socketManager).changeClientAddress(argThat(address -> address.equals(defaultClientAddress)));
    }

    @Test
    void whenClientMigratesBackToPreviousAddressAfterLongTimeServerShouldNotMigrateWithoutRevalidation() {
        // Given
        InetSocketAddress newAddress = new InetSocketAddress("localhost", 59643);
        PacketMetaData packetMetaData = metaDataFor(1200, newAddress);
        pathValidator.checkSourceAddress(normalPacket(), packetMetaData);
        PathChallengeFrame pathChallengeFrame = capturePathChallengeFrame();
        PathResponseFrame pathResponseFrame = new PathResponseFrame(Version.getDefault(), pathChallengeFrame.getData());
        pathValidator.checkPathResponse(pathResponseFrame, metaDataFor(1200, newAddress));

        assertThat(pathValidator.isValidated(newAddress)).isTrue();
        verify(socketManager).changeClientAddress(argThat(address -> address.equals(newAddress)));
        clearInvocations(socketManager);

        // When
        Duration longTime = Duration.ofMinutes(13);
        testClock.fastForward((int) longTime.toMillis());
        pathValidator.checkSourceAddress(normalPacket(), metaDataFor(684, defaultClientAddress));

        // Then
        verify(socketManager, never()).changeClientAddress(any(InetSocketAddress.class));
    }

    @Test
    void whenClientMigratesBackToPreviousLongTimeUsedAddressServerShouldMigrateImmediately() {
        // Given
        Duration longTime = Duration.ofMinutes(15);
        testClock.fastForward((int) longTime.toMillis());
        pathValidator.checkSourceAddress(normalPacket(), metaDataFor(1200, defaultClientAddress));

        // New client address
        InetSocketAddress newAddress = new InetSocketAddress("localhost", 59643);
        PacketMetaData packetMetaData = metaDataFor(1200, newAddress);
        pathValidator.checkSourceAddress(normalPacket(), packetMetaData);

        // Respond to validation
        PathChallengeFrame pathChallengeFrame = capturePathChallengeFrame();
        PathResponseFrame pathResponseFrame = new PathResponseFrame(Version.getDefault(), pathChallengeFrame.getData());
        pathValidator.checkPathResponse(pathResponseFrame, metaDataFor(1200, newAddress));

        clearInvocations(socketManager);

        // When
        pathValidator.checkSourceAddress(normalPacket(), metaDataFor(684, defaultClientAddress));

        // Then
        verify(socketManager).changeClientAddress(argThat(address -> address.equals(defaultClientAddress)));
    }

    @Test
    void numberOfStoredPathValidationsShouldBeLimited() {
        // Given
        testClock.fastForward(1);
        int basePortNumber = 59643;
        for (int i = 0; i < 69; i++) {
            int newPort = basePortNumber + i;
            InetSocketAddress newAddress = new InetSocketAddress("localhost", newPort);
            PacketMetaData packetMetaData = metaDataFor(1200, newAddress);
            pathValidator.checkSourceAddress(normalPacket(), packetMetaData);

            testClock.fastForward(1);
            PathChallengeFrame pathChallengeFrame = capturePathChallengeFrame();
            PathResponseFrame pathResponseFrame = new PathResponseFrame(Version.getDefault(), pathChallengeFrame.getData());
            pathValidator.checkPathResponse(pathResponseFrame, metaDataFor(1200, newAddress));

            testClock.fastForward(1);
            assertThat(pathValidator.isValidated(newAddress)).isTrue();
        }
        clearInvocations(socketManager);

        // When
        pathValidator.checkSourceAddress(normalPacket(), metaDataFor(684, defaultClientAddress));

        // Then
        verify(socketManager, never()).changeClientAddress(argThat(address -> address.equals(defaultClientAddress)));
    }
    //endregion

    //region utility methods
    @Test
    void whenPacketContainsOnlyProbingFramesItShouldBeConsideredProbingPacket() {
        // Given
        List<QuicFrame> allProbingFrames = List.of(new PathChallengeFrame(Version.getDefault(), new byte[8]),
                new PathResponseFrame(Version.getDefault(), new byte[8]),
                new NewConnectionIdFrame(Version.getDefault(), 0, 0, new byte[8]),
                new Padding(10));

        QuicPacket packet = new ShortHeaderPacket(Version.getDefault(), new byte[8], allProbingFrames);

        // When
        boolean isProbingPacket = PathValidator.isProbingPacket(packet);

        // Then
        assertThat(isProbingPacket).isTrue();
    }

    @Test
    void whenPacketContainsOtherThanProbingFramesItShouldBeConsideredNotProbingPacket() {
        // Given
        List<QuicFrame> frames = List.of(
                new PathResponseFrame(Version.getDefault(), new byte[8]),
                new MaxStreamsFrame(100, true));

        QuicPacket packet = new ShortHeaderPacket(Version.getDefault(), new byte[8], frames);

        // When
        boolean isProbingPacket = PathValidator.isProbingPacket(packet);

        // Then
        assertThat(isProbingPacket).isFalse();
    }
    //endregion

    //region helper methods
    private PacketMetaData metaDataFor(int packetSize, InetSocketAddress sourceAddress) {
        return new PacketMetaData(Instant.now(), sourceAddress, 0, packetSize);
    }

    private PathChallengeFrame capturePathChallengeFrame() {
        ArgumentCaptor<QuicFrame> captor = ArgumentCaptor.forClass(QuicFrame.class);
        verify(sender).sendAlternateAddress(captor.capture(), any(InetSocketAddress.class));
        clearInvocations(sender);

        return (PathChallengeFrame) captor.getValue();
    }

    private QuicPacket normalPacket() {
        return normalPacket(68);
    }

    private QuicPacket normalPacket(long pn) {
        return new ShortHeaderPacket(pn, new byte[8], new StreamFrame(0, new byte[1130], false));
    }
    //endregion
}