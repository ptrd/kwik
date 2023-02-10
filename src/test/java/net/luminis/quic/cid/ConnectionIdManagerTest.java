/*
 * Copyright © 2022, 2023 Peter Doornbosch
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
package net.luminis.quic.cid;

import net.luminis.quic.TestUtils;
import net.luminis.quic.Version;
import net.luminis.quic.frame.NewConnectionIdFrame;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.frame.RetireConnectionIdFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.send.Sender;
import net.luminis.quic.server.ServerConnectionRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static net.luminis.quic.TestUtils.*;
import static net.luminis.quic.cid.ConnectionIdManager.MAX_CIDS_PER_CONNECTION;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;


class ConnectionIdManagerTest {

    private ServerConnectionRegistry connectionRegistry;
    private Sender sender;
    private ConnectionIdManager serverConnectionIdManager;
    private ConnectionIdManager clientConnectionIdManager;
    private BiConsumer<Integer, String> closeCallback;
    private byte[] initialClientCid;

    @BeforeEach
    void initObjectUnderTest() {
        connectionRegistry = mock(ServerConnectionRegistry.class);
        sender = mock(Sender.class);
        closeCallback = mock(BiConsumer.class);
        initialClientCid = new byte[] { 0x7f, 0x10, 0x49, 0x03 };
        serverConnectionIdManager = new ConnectionIdManager(initialClientCid, new byte[8], 6, 2, connectionRegistry, closeCallback, mock(Logger.class));
        serverConnectionIdManager.setSender(sender);
        clientConnectionIdManager = new ConnectionIdManager(4, 2, closeCallback, mock(Logger.class));
        clientConnectionIdManager.setSender(sender);
    }

    @Test
    void whenConnectionCreatedNewConnectionIdsShouldBeSent() {
        // Given
        serverConnectionIdManager.registerPeerCidLimit(2);

        // When
        serverConnectionIdManager.handshakeFinished();

        // Then
        verify(sender, atLeastOnce()).send(argThat(frame -> frame instanceof NewConnectionIdFrame), any(), any(Consumer.class));
    }

    @Test
    void firstNewConnectionIdSentShouldHaveSequenceNumberOne() {
        // Given
        serverConnectionIdManager.registerPeerCidLimit(4);

        // When
        serverConnectionIdManager.handshakeFinished();

        // Then
        ArgumentCaptor<QuicFrame> captor = ArgumentCaptor.forClass(QuicFrame.class);
        verify(sender, times(3)).send(captor.capture(), any(), any(Consumer.class));
        QuicFrame firstFrame = captor.getAllValues().get(0);
        assertThat(((NewConnectionIdFrame) firstFrame).getSequenceNr()).isEqualTo(1);
    }

    @Test
    void initialCidsShouldMatchPeerLimitMinusOne() {
        // Given
        serverConnectionIdManager.registerPeerCidLimit(4);

        // When
        serverConnectionIdManager.handshakeFinished();

        // Then
        verify(sender, times(3)).send(argThat(frame -> frame instanceof NewConnectionIdFrame), any(), any(Consumer.class));
    }

    @Test
    void whenPeerLimitIsLargeinitialCidsShouldMatchServerLimit() {
        // Given
        serverConnectionIdManager.registerPeerCidLimit(64);

        // When
        serverConnectionIdManager.handshakeFinished();

        // Then
        verify(sender, times(MAX_CIDS_PER_CONNECTION - 1)).send(argThat(frame -> frame instanceof NewConnectionIdFrame), any(), any(Consumer.class));
    }
    
    @Test
    void retireConnectionIdShouldLeadToDeregistering() {
        // Given
        byte[] originalCid = serverConnectionIdManager.getActiveConnectionIds().get(0);
        serverConnectionIdManager.registerPeerCidLimit(4);
        serverConnectionIdManager.handshakeFinished();

        // When
        serverConnectionIdManager.process(new RetireConnectionIdFrame(Version.getDefault(), 0), null);

        // Then
        ArgumentCaptor<byte[]> captor = ArgumentCaptor.forClass(byte[].class);
        verify(connectionRegistry).deregisterConnectionId(captor.capture());
        assertThat(captor.getValue()).isEqualTo(originalCid);
    }

    @Test
    void retireConnectionIdShouldLeadToSendingNew() {
        // Given
        serverConnectionIdManager.registerPeerCidLimit(2);
        serverConnectionIdManager.handshakeFinished();
        clearInvocations(sender);

        // When
        serverConnectionIdManager.process(new RetireConnectionIdFrame(Version.getDefault(), 0), null);

        // Then
        verify(sender).send(argThat(f -> f instanceof NewConnectionIdFrame), any(), any(Consumer.class));
    }

    @Test
    void retiringConnectionIdAlreadyRetiredDoesNothing() {
        // Given
        serverConnectionIdManager.registerPeerCidLimit(2);
        serverConnectionIdManager.handshakeFinished();
        serverConnectionIdManager.process(new RetireConnectionIdFrame(Version.getDefault(), 0), null);
        clearInvocations(sender);

        // When
        serverConnectionIdManager.process(new RetireConnectionIdFrame(Version.getDefault(), 0), null);

        // Then
        verify(sender, never()).send(any(QuicFrame.class), any(), any(Consumer.class));
    }

    @Test
    void retiringNonExistentSequenceNumberLeadsToConnectionClose() {
        // Given
        serverConnectionIdManager.registerPeerCidLimit(2);
        serverConnectionIdManager.handshakeFinished();

        // When
        serverConnectionIdManager.process(new RetireConnectionIdFrame(Version.getDefault(), 2), null);

        // Then
        ArgumentCaptor<Integer> captor = ArgumentCaptor.forClass(Integer.class);
        verify(closeCallback).accept(captor.capture(), anyString());
        assertThat(captor.getValue()).isEqualTo(0x0a);
    }

    @Test
    void retiringConnectionIdUsedAsDestinationConnectionIdLeadsToConnectionClose() {
        // Given
        serverConnectionIdManager.registerPeerCidLimit(2);
        serverConnectionIdManager.handshakeFinished();

        // When
        serverConnectionIdManager.process(new RetireConnectionIdFrame(Version.getDefault(), 0), serverConnectionIdManager.getActiveConnectionIds().get(0));

        // Then
        ArgumentCaptor<Integer> captor = ArgumentCaptor.forClass(Integer.class);
        verify(closeCallback).accept(captor.capture(), anyString());
        assertThat(captor.getValue()).isEqualTo(0x0a);
    }

    @Test
    void initiallyThereShouldBeExactlyOneActiveCid() {
        assertThat(serverConnectionIdManager.getActiveConnectionIds()).hasSize(1);
    }

    @Test
    void initiallyAtLeastOneNewCidShouldBeAccepted() {
        // Given

        // When
        serverConnectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 2, 0, new byte[4]));

        // Then
        assertThat(serverConnectionIdManager.getActivePeerConnectionIds()).hasSize(2);
    }

    @Test
    void whenNumberOfActiveCidsExceedsLimitConnectionIdLimitErrorIsThrown() {
        // Given
        serverConnectionIdManager = new ConnectionIdManager(new byte[4], new byte[8], 6, 3, connectionRegistry, closeCallback, mock(Logger.class));
        serverConnectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 1, 0, new byte[4]));
        serverConnectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 2, 0, new byte[4]));

        // When
        serverConnectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 3, 0, new byte[4]));

        // Then
        ArgumentCaptor<Integer> captor = ArgumentCaptor.forClass(Integer.class);
        verify(closeCallback).accept(captor.capture(), anyString());
        assertThat(captor.getValue()).isEqualTo(0x09);
    }

    @Test
    void repeatingNewCidWithSequenceNumberShouldNotLeadToError() {
        // Given
        serverConnectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 1, 0, new byte[4]));

        // When
        serverConnectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 1, 0, new byte[4]));

        // Then
        verify(closeCallback, never()).accept(anyInt(), anyString());
    }

    @Test
    void invalidRetirePriorToFieldShouldLeadToFrameEncodingError() {
        // Given

        // When
        serverConnectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 1, 2, new byte[4]));

        // Then
        ArgumentCaptor<Integer> captor = ArgumentCaptor.forClass(Integer.class);
        verify(closeCallback).accept(captor.capture(), anyString());
        assertThat(captor.getValue()).isEqualTo(0x07);
    }

    @Test
    void newConnectionIdFrameWithIncreasedRetirePriorToFieldLeadsToRetireConnectionIdFrame() {
        // Given
        serverConnectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 0, 0, new byte[4]));
        // When
        serverConnectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 1, 1, new byte[4]));

        // Then
        verify(sender, atLeastOnce()).send(argThat(f -> f instanceof RetireConnectionIdFrame), any(), any(Consumer.class));
    }

    @Test
    void newConnectionIdFrameWithIncreasedRetirePriorToFieldLeadsToDecrementOfActiveCids() {
        // Given
        serverConnectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 1, 0, new byte[4]));

        // When
        serverConnectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 2, 1, new byte[4]));

        // Then
        assertThat(serverConnectionIdManager.getActivePeerConnectionIds()).hasSize(2);
        verify(closeCallback, never()).accept(anyInt(), anyString());
    }

    @Test
    void retiredCidShouldNotBeUsedAnymoreAsDestination() {
        // Given
        byte[] originalDcid = serverConnectionIdManager.getCurrentPeerConnectionId();
        serverConnectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 1, 0, new byte[] { 0x34, 0x1f, 0x5a, 0x55 }));

        // When
        serverConnectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 2, 1, new byte[] { 0x5b, 0x2e, 0x1a, 0x44 }));

        // Then
        assertThat(serverConnectionIdManager.getCurrentPeerConnectionId()).isNotEqualTo(originalDcid);
    }

    @Test
    void newConnectionIdWithSequenceNumberZeroShouldFail() {
        // Given
        byte[] originalDcid = serverConnectionIdManager.getCurrentPeerConnectionId();
        byte[] newDcid = Arrays.copyOf(originalDcid, originalDcid.length);
        newDcid[0] += 1;  // So now the two or definitely different

        // When
        serverConnectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 0, 0, newDcid));

        // Then
        ArgumentCaptor<Integer> captor = ArgumentCaptor.forClass(Integer.class);
        verify(closeCallback).accept(captor.capture(), anyString());
        assertThat(captor.getValue()).isEqualTo(0x0a);
    }

    @Test
    void whenUsingZeroLengthConnectionIdNewConnectionIdFrameShouldLeadToProtocolViolationError() {
        // Given
        serverConnectionIdManager = new ConnectionIdManager(new byte[0], new byte[8], 6, 2, connectionRegistry, closeCallback, mock(Logger.class));
        // When
        serverConnectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 1, 0, new byte[4]));

        // Then
        ArgumentCaptor<Integer> captor = ArgumentCaptor.forClass(Integer.class);
        verify(closeCallback).accept(captor.capture(), anyString());
        assertThat(captor.getValue()).isEqualTo(0x0a);
    }

    @Test
    void initialConnectionIdShouldNotChange() {
        // Given
        byte[] initialConnectionId = serverConnectionIdManager.getInitialConnectionId();

        // When
        serverConnectionIdManager.process(new RetireConnectionIdFrame(Version.getDefault(), 0), new byte[3]);

        // Then
        assertThat(serverConnectionIdManager.getInitialConnectionId()).isEqualTo(initialConnectionId);
    }

    @Test
    void testValidateInitialPeerConnectionId() {
        // Given
        byte[] peerCid = new byte[] { 0x06, 0x0f, 0x08, 0x0b };
        serverConnectionIdManager = new ConnectionIdManager(peerCid, new byte[8], 6, 2, connectionRegistry, closeCallback, mock(Logger.class));

        // Then
        assertThat(serverConnectionIdManager.validateInitialPeerConnectionId(peerCid)).isTrue();
    }

    @Test
    void whenReorderedNewConnectionIdIsAlreadyRetiredRetireConnectionIdFrameShouldBeSent() {
        // Given
        serverConnectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 2, 2, new byte[4]));

        // When
        serverConnectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 1, 0, new byte[4]));

        // Then
        ArgumentCaptor<QuicFrame> captor = ArgumentCaptor.forClass(QuicFrame.class);
        verify(sender, atLeastOnce()).send(captor.capture(), any(), any(Consumer.class));
        List<Integer> retiredSeqNr = captor.getAllValues().stream()
                .filter(f -> f instanceof RetireConnectionIdFrame)
                .map(f -> ((RetireConnectionIdFrame) f).getSequenceNr())
                .collect(Collectors.toList());
        assertThat(retiredSeqNr).contains(1);
    }

    @Test
    void whenSendingNewConnectionIdRetirePriorToIsSet() {
        serverConnectionIdManager.sendNewConnectionId(1);

        ArgumentCaptor<QuicFrame> captor = ArgumentCaptor.forClass(QuicFrame.class);
        verify(sender, atLeastOnce()).send(captor.capture(), any(), any(Consumer.class));
        assertThat(captor.getValue() instanceof NewConnectionIdFrame);
        assertThat(((NewConnectionIdFrame) captor.getValue()).getRetirePriorTo()).isEqualTo(1);
    }

    @Test
    void whenPreviouslyUnusedConnectionIdIsUsedNewConnectionIdIsSent() {
        // Given
        int maxCids = 3;
        serverConnectionIdManager.registerPeerCidLimit(maxCids);
        serverConnectionIdManager.sendNewConnectionId(0);
        clearInvocations(sender);
        assertThat(serverConnectionIdManager.getActiveConnectionIds()).hasSize(2);

        // When
        serverConnectionIdManager.getActiveConnectionIds().forEach(cid -> {
                serverConnectionIdManager.registerConnectionIdInUse(cid);
        });

        // Then
        verify(sender, atLeastOnce()).send(argThat(f -> f instanceof NewConnectionIdFrame), any(), any(Consumer.class));
    }

    @Test
    void whenMaxCidsIsReachedRegisterUnusedDoesNotLeadToNew() {
        // Given
        serverConnectionIdManager = new ConnectionIdManager(new byte[4], new byte[8], 4, 2, connectionRegistry, closeCallback, mock(Logger.class));
        serverConnectionIdManager.setSender(sender);
        int maxCids = 6;
        serverConnectionIdManager.registerPeerCidLimit(maxCids);
        serverConnectionIdManager.handshakeFinished();
        clearInvocations(sender);
        assertThat(serverConnectionIdManager.getActiveConnectionIds()).hasSize(maxCids);

        // When
        serverConnectionIdManager.getActiveConnectionIds().forEach(cid -> {
            serverConnectionIdManager.registerConnectionIdInUse(cid);
        });

        // Then
        verify(sender, never()).send(argThat(f -> f instanceof NewConnectionIdFrame), any(), any(Consumer.class));
    }

    void testValidateRetrySourceConnectionId() {
        // Given
        serverConnectionIdManager = new ConnectionIdManager(new byte[8], new byte[8], 6, 2, connectionRegistry, closeCallback, mock(Logger.class));
        byte[] retryCid = new byte[] { 0x06, 0x0f, 0x08, 0x0b };

        // When
        serverConnectionIdManager.registerRetrySourceConnectionId(retryCid);

        // Then
        assertThat(serverConnectionIdManager.validateRetrySourceConnectionId(retryCid)).isTrue();
    }

    @Test
    void whenActiveConnectionIdLimitReachedReceivingRetireShouldNotLeadToNew() {
        // Given
        serverConnectionIdManager.sendNewConnectionId(0);

        // When
        serverConnectionIdManager.sendNewConnectionId(1);
        clearInvocations(sender);
        serverConnectionIdManager.process(new RetireConnectionIdFrame(Version.getDefault(), 0), new byte[3]);

        // Then
        verify(sender, never()).send(any(QuicFrame.class), any(), any(Consumer.class));
    }

    @Test
    void whenConnectionIdAlreadyRetiredReceivingRetireShouldNotLeadToNew() {
        // Given
        serverConnectionIdManager.sendNewConnectionId(0);
        serverConnectionIdManager.process(new RetireConnectionIdFrame(Version.getDefault(), 0), new byte[3]);
        clearInvocations(sender);
        assertThat(serverConnectionIdManager.getActiveConnectionIds()).hasSize(2);  // Because retire triggers new.

        // When
        serverConnectionIdManager.process(new RetireConnectionIdFrame(Version.getDefault(), 0), new byte[3]);

        // Then
        verify(sender, never()).send(any(QuicFrame.class), any(), any(Consumer.class));
    }

    @Test
    void testRegisterInitialPeerCid() throws Exception {
        // Given
        InetSocketAddress clientAddress = getArbitraryLocalAddress();
        clientConnectionIdManager.registerClientAddress(clientAddress);
        assertThat(clientConnectionIdManager.getAllPeerConnectionIds().get(0).getConnectionId()).isNotEqualTo(new byte[] { 0x01, 0x02, 0x03, 0x04 });

        // When
        clientConnectionIdManager.registerInitialPeerCid(new byte[] { 0x01, 0x02, 0x03, 0x04 });

        // Then
        assertThat(clientConnectionIdManager.getAllPeerConnectionIds().get(0).getConnectionId()).isEqualTo(new byte[] { 0x01, 0x02, 0x03, 0x04 });
        assertThat(clientConnectionIdManager.getPeerConnectionId(clientAddress)).isEqualTo(new byte[] { 0x01, 0x02, 0x03, 0x04 });
    }

    @Test
    void initialStatelessResetTokenShouldBeRecognizedAsSuch() {
        byte[] statelessResetToken = new byte[]{ 8, 12, 45, 31, 85, 123, 61, 127, 39, 43, 42 };
        clientConnectionIdManager.setInitialStatelessResetToken(statelessResetToken);

        assertThat(clientConnectionIdManager.isStatelessResetToken(statelessResetToken)).isTrue();
    }

    @Test
    void statelessResetTokenFromNewConnectiondIdFrameIsNotUsedAsSuchWhenConnectionIdNotUsed() {
        // When
        NewConnectionIdFrame newConnectionIdFrame = new NewConnectionIdFrame(Version.getDefault(), 1, 0, new byte[]{ 0x35, 0x7a, 0x0f, 0x69 });
        clientConnectionIdManager.process(newConnectionIdFrame);

        // Then
        assertThat(clientConnectionIdManager.isStatelessResetToken(newConnectionIdFrame.getStatelessResetToken())).isFalse();
    }

    @Test
    void statelessResetTokenFromNewConnectiondIdFrameIsRecognisedWhenConnectionIdIsUsed() throws Exception {
        // Given
        clientConnectionIdManager.registerClientAddress(getArbitraryLocalAddress());
        
        // When
        NewConnectionIdFrame newConnectionIdFrame = new NewConnectionIdFrame(Version.getDefault(), 1, 0, new byte[]{ 0x35, 0x7a, 0x0f, 0x69 });
        clientConnectionIdManager.process(newConnectionIdFrame);
        clientConnectionIdManager.nextPeerId();

        // Then
        assertThat(clientConnectionIdManager.isStatelessResetToken(newConnectionIdFrame.getStatelessResetToken())).isTrue();
    }

    @Test
    void cidForInitialClientAddressIsInitialCid() throws Exception {
        // Given
        InetSocketAddress clientAddress = getArbitraryLocalAddress();
        serverConnectionIdManager.registerClientAddress(clientAddress);

        // When
        byte[] peerConnectionId = serverConnectionIdManager.getPeerConnectionId(clientAddress);

        // Then
        assertThat(peerConnectionId).isEqualTo(initialClientCid);
    }

    @Test
    void cidForChangedClientAddressIsUnequalToInitialCid() throws Exception {
        // Given
        InetSocketAddress clientAddress = getArbitraryLocalAddress();
        serverConnectionIdManager.registerClientAddress(clientAddress);
        serverConnectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 1, 0, new byte[] { 0x35, 0x7a, 0x0f, 0x69 }));

        // When
        InetAddress otherAddress = InetAddress.getByAddress(new byte[] { 8, 8, 8, 8 });
        byte[] peerConnectionId = serverConnectionIdManager.getPeerConnectionId(new InetSocketAddress(otherAddress, 4433));

        // Then
        assertThat(peerConnectionId).isNotEqualTo(initialClientCid);
    }

    @Test
    void cidForChangedClientAddressWhenNoUnusedCids() throws Exception {
        // Given
        InetSocketAddress clientAddress = getArbitraryLocalAddress();
        serverConnectionIdManager.registerClientAddress(clientAddress);

        // When
        InetAddress otherAddress = InetAddress.getByAddress(new byte[] { 8, 8, 8, 8 });
        byte[] peerConnectionId = serverConnectionIdManager.getPeerConnectionId(new InetSocketAddress(otherAddress, 4433));

        // Then
        assertThat(peerConnectionId).isEqualTo(initialClientCid);
    }

    @Test
    void next() throws Exception {
        // Given
        InetSocketAddress clientAddress = getArbitraryLocalAddress();
        serverConnectionIdManager.registerClientAddress(clientAddress);
        serverConnectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 1, 0, new byte[] { 0x35, 0x7a, 0x0f, 0x69 }));

        // When
        serverConnectionIdManager.nextPeerId();

        // Then
        byte[] peerConnectionId = serverConnectionIdManager.getPeerConnectionId(clientAddress);

        // Then
        assertThat(peerConnectionId).isNotEqualTo(initialClientCid);
    }
}
