/*
 * Copyright © 2022, 2023, 2024, 2025 Peter Doornbosch
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

import net.luminis.quic.impl.Version;
import net.luminis.quic.frame.NewConnectionIdFrame;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.frame.RetireConnectionIdFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.send.Sender;
import net.luminis.quic.server.ServerConnectionRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Arrays;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static net.luminis.quic.cid.ConnectionIdManager.MAX_CIDS_PER_CONNECTION;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;


class ConnectionIdManagerTest {

    private ServerConnectionRegistry connectionRegistry;
    private Sender sender;
    private ConnectionIdManager connectionIdManager;
    private BiConsumer<Integer, String> closeCallback;

    @BeforeEach
    void initObjectUnderTest() {
        connectionRegistry = mock(ServerConnectionRegistry.class);
        sender = mock(Sender.class);
        closeCallback = mock(BiConsumer.class);
        connectionIdManager = new ConnectionIdManager(new byte[4], new byte[8], 6, 2, connectionRegistry, sender, closeCallback, mock(Logger.class));
    }

    @Test
    void whenConnectionCreatedNewConnectionIdsShouldBeSent() {
        // Given
        connectionIdManager.registerPeerCidLimit(2);

        // When
        connectionIdManager.handshakeFinished();

        // Then
        verify(sender, atLeastOnce()).send(argThat(frame -> frame instanceof NewConnectionIdFrame), any(), any(Consumer.class));
    }

    @Test
    void firstNewConnectionIdSentShouldHaveSequenceNumberOne() {
        // Given
        connectionIdManager.registerPeerCidLimit(4);

        // When
        connectionIdManager.handshakeFinished();

        // Then
        ArgumentCaptor<QuicFrame> captor = ArgumentCaptor.forClass(QuicFrame.class);
        verify(sender, times(3)).send(captor.capture(), any(), any(Consumer.class));
        QuicFrame firstFrame = captor.getAllValues().get(0);
        assertThat(((NewConnectionIdFrame) firstFrame).getSequenceNr()).isEqualTo(1);
    }

    @Test
    void initialCidsShouldMatchPeerLimitMinusOne() {
        // Given
        connectionIdManager.registerPeerCidLimit(4);

        // When
        connectionIdManager.handshakeFinished();

        // Then
        verify(sender, times(3)).send(argThat(frame -> frame instanceof NewConnectionIdFrame), any(), any(Consumer.class));
    }

    @Test
    void whenPeerLimitIsLargeinitialCidsShouldMatchServerLimit() {
        // Given
        connectionIdManager.registerPeerCidLimit(64);

        // When
        connectionIdManager.handshakeFinished();

        // Then
        verify(sender, times(MAX_CIDS_PER_CONNECTION - 1)).send(argThat(frame -> frame instanceof NewConnectionIdFrame), any(), any(Consumer.class));
    }
    
    @Test
    void retireConnectionIdShouldLeadToDeregistering() {
        // Given
        byte[] originalCid = connectionIdManager.getActiveConnectionIds().get(0);
        connectionIdManager.registerPeerCidLimit(4);
        connectionIdManager.handshakeFinished();

        // When
        connectionIdManager.process(new RetireConnectionIdFrame(Version.getDefault(), 0), null);

        // Then
        ArgumentCaptor<byte[]> captor = ArgumentCaptor.forClass(byte[].class);
        verify(connectionRegistry).deregisterConnectionId(captor.capture());
        assertThat(captor.getValue()).isEqualTo(originalCid);
    }

    @Test
    void retireConnectionIdShouldLeadToSendingNew() {
        // Given
        connectionIdManager.registerPeerCidLimit(2);
        connectionIdManager.handshakeFinished();
        clearInvocations(sender);

        // When
        connectionIdManager.process(new RetireConnectionIdFrame(Version.getDefault(), 0), null);

        // Then
        verify(sender).send(argThat(f -> f instanceof NewConnectionIdFrame), any(), any(Consumer.class));
    }

    @Test
    void retiringConnectionIdAlreadyRetiredDoesNothing() {
        // Given
        connectionIdManager.registerPeerCidLimit(2);
        connectionIdManager.handshakeFinished();
        connectionIdManager.process(new RetireConnectionIdFrame(Version.getDefault(), 0), null);
        clearInvocations(sender);

        // When
        connectionIdManager.process(new RetireConnectionIdFrame(Version.getDefault(), 0), null);

        // Then
        verify(sender, never()).send(any(QuicFrame.class), any(), any(Consumer.class));
    }

    @Test
    void retiringNonExistentSequenceNumberLeadsToConnectionClose() {
        // Given
        connectionIdManager.registerPeerCidLimit(2);
        connectionIdManager.handshakeFinished();

        // When
        connectionIdManager.process(new RetireConnectionIdFrame(Version.getDefault(), 2), null);

        // Then
        ArgumentCaptor<Integer> captor = ArgumentCaptor.forClass(Integer.class);
        verify(closeCallback).accept(captor.capture(), anyString());
        assertThat(captor.getValue()).isEqualTo(0x0a);
    }

    @Test
    void retiringConnectionIdUsedAsDestinationConnectionIdLeadsToConnectionClose() {
        // Given
        connectionIdManager.registerPeerCidLimit(2);
        connectionIdManager.handshakeFinished();

        // When
        connectionIdManager.process(new RetireConnectionIdFrame(Version.getDefault(), 0), connectionIdManager.getActiveConnectionIds().get(0));

        // Then
        ArgumentCaptor<Integer> captor = ArgumentCaptor.forClass(Integer.class);
        verify(closeCallback).accept(captor.capture(), anyString());
        assertThat(captor.getValue()).isEqualTo(0x0a);
    }

    @Test
    void initiallyThereShouldBeExactlyOneActiveCid() {
        assertThat(connectionIdManager.getActiveConnectionIds()).hasSize(1);
    }

    @Test
    void checkActiveCid() {
        // Given
        byte[] originalCid = connectionIdManager.getActiveConnectionIds().get(0);
        byte[] cid = Arrays.copyOf(originalCid, originalCid.length);

        // When
        boolean isActive = connectionIdManager.isActiveCid(cid);

        // Then
        assertThat(isActive).isTrue();
    }

    @Test
    void initiallyAtLeastOneNewCidShouldBeAccepted() {
        // Given

        // When
        connectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 2, 0, new byte[4]));

        // Then
        assertThat(connectionIdManager.getActivePeerConnectionIds()).hasSize(2);
    }

    @Test
    void whenNumberOfActiveCidsExceedsLimitConnectionIdLimitErrorIsThrown() {
        // Given
        connectionIdManager = new ConnectionIdManager(new byte[4], new byte[8], 6, 3, connectionRegistry, sender, closeCallback, mock(Logger.class));
        connectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 1, 0, new byte[4]));
        connectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 2, 0, new byte[4]));

        // When
        connectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 3, 0, new byte[4]));

        // Then
        ArgumentCaptor<Integer> captor = ArgumentCaptor.forClass(Integer.class);
        verify(closeCallback).accept(captor.capture(), anyString());
        assertThat(captor.getValue()).isEqualTo(0x09);
    }

    @Test
    void repeatingNewCidWithSequenceNumberShouldNotLeadToError() {
        // Given
        connectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 1, 0, new byte[4]));

        // When
        connectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 1, 0, new byte[4]));

        // Then
        verify(closeCallback, never()).accept(anyInt(), anyString());
    }

    @Test
    void invalidRetirePriorToFieldShouldLeadToFrameEncodingError() {
        // Given

        // When
        connectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 1, 2, new byte[4]));

        // Then
        ArgumentCaptor<Integer> captor = ArgumentCaptor.forClass(Integer.class);
        verify(closeCallback).accept(captor.capture(), anyString());
        assertThat(captor.getValue()).isEqualTo(0x07);
    }

    @Test
    void newConnectionIdFrameWithIncreasedRetirePriorToFieldLeadsToRetireConnectionIdFrame() {
        // Given
        connectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 0, 0, new byte[4]));

        // When
        connectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 1, 1, new byte[4]));

        // Then
        verify(sender, atLeastOnce()).send(argThat(f -> f instanceof RetireConnectionIdFrame), any(), any(Consumer.class));
    }

    @Test
    void newConnectionIdFrameWithIncreasedRetirePriorToFieldLeadsToDecrementOfActiveCids() {
        // Given
        connectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 1, 0, new byte[4]));

        // When
        connectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 2, 1, new byte[4]));

        // Then
        assertThat(connectionIdManager.getActivePeerConnectionIds()).hasSize(2);
        verify(closeCallback, never()).accept(anyInt(), anyString());
    }

    @Test
    void retiredCidShouldNotBeUsedAnymoreAsDestination() {
        // Given
        byte[] originalDcid = connectionIdManager.getCurrentPeerConnectionId();
        connectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 1, 0, new byte[] { 0x34, 0x1f, 0x5a, 0x55 }));

        // When
        connectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 2, 1, new byte[] { 0x5b, 0x2e, 0x1a, 0x44 }));

        // Then
        assertThat(connectionIdManager.getCurrentPeerConnectionId()).isNotEqualTo(originalDcid);
    }

    @Test
    void newConnectionIdWithSequenceNumberZeroShouldFail() {
        // Given
        byte[] originalDcid = connectionIdManager.getCurrentPeerConnectionId();
        byte[] newDcid = Arrays.copyOf(originalDcid, originalDcid.length);
        newDcid[0] += 1;  // So now the two or definitely different

        // When
        connectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 0, 0, newDcid));

        // Then
        ArgumentCaptor<Integer> captor = ArgumentCaptor.forClass(Integer.class);
        verify(closeCallback).accept(captor.capture(), anyString());
        assertThat(captor.getValue()).isEqualTo(0x0a);
    }

    @Test
    void whenUsingZeroLengthConnectionIdNewConnectionIdFrameShouldLeadToProtocolViolationError() {
        // Given
        connectionIdManager = new ConnectionIdManager(new byte[0], new byte[8], 6, 2, connectionRegistry, sender, closeCallback, mock(Logger.class));
        // When
        connectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 1, 0, new byte[4]));

        // Then
        ArgumentCaptor<Integer> captor = ArgumentCaptor.forClass(Integer.class);
        verify(closeCallback).accept(captor.capture(), anyString());
        assertThat(captor.getValue()).isEqualTo(0x0a);
    }

    @Test
    void initialConnectionIdShouldNotChange() {
        // Given
        byte[] initialConnectionId = connectionIdManager.getInitialConnectionId();

        // When
        connectionIdManager.process(new RetireConnectionIdFrame(Version.getDefault(), 0), new byte[3]);

        // Then
        assertThat(connectionIdManager.getInitialConnectionId()).isEqualTo(initialConnectionId);
    }

    @Test
    void testValidateInitialPeerConnectionId() {
        // Given
        byte[] peerCid = new byte[] { 0x06, 0x0f, 0x08, 0x0b };
        connectionIdManager = new ConnectionIdManager(peerCid, new byte[8], 6, 2, connectionRegistry, sender, closeCallback, mock(Logger.class));

        // Then
        assertThat(connectionIdManager.validateInitialPeerConnectionId(peerCid)).isTrue();
    }

    @Test
    void whenReorderedNewConnectionIdIsAlreadyRetiredRetireConnectionIdFrameShouldBeSent() {
        // Given
        connectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 2, 2, new byte[4]));

        // When
        connectionIdManager.process(new NewConnectionIdFrame(Version.getDefault(), 1, 0, new byte[4]));

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
        connectionIdManager.sendNewConnectionId(1);

        ArgumentCaptor<QuicFrame> captor = ArgumentCaptor.forClass(QuicFrame.class);
        verify(sender, atLeastOnce()).send(captor.capture(), any(), any(Consumer.class));
        assertThat(captor.getValue()).isInstanceOf(NewConnectionIdFrame.class);
        assertThat(((NewConnectionIdFrame) captor.getValue()).getRetirePriorTo()).isEqualTo(1);
    }

    @Test
    void whenPreviouslyUnusedConnectionIdIsUsedNewConnectionIdIsSent() {
        // Given
        int maxCids = 3;
        connectionIdManager.registerPeerCidLimit(maxCids);
        connectionIdManager.sendNewConnectionId(0);
        clearInvocations(sender);
        assertThat(connectionIdManager.getActiveConnectionIds()).hasSize(2);

        // When
        connectionIdManager.getActiveConnectionIds().forEach(cid -> {
                connectionIdManager.registerConnectionIdInUse(cid);
        });

        // Then
        verify(sender, atLeastOnce()).send(argThat(f -> f instanceof NewConnectionIdFrame), any(), any(Consumer.class));
    }

    @Test
    void whenMaxCidsIsReachedRegisterUnusedDoesNotLeadToNew() {
        // Given
        connectionIdManager = new ConnectionIdManager(new byte[4], new byte[8], 4, 2, connectionRegistry, sender, closeCallback, mock(Logger.class));
        int maxCids = 6;
        connectionIdManager.registerPeerCidLimit(maxCids);
        connectionIdManager.handshakeFinished();
        clearInvocations(sender);
        assertThat(connectionIdManager.getActiveConnectionIds()).hasSize(maxCids);

        // When
        connectionIdManager.getActiveConnectionIds().forEach(cid -> {
            connectionIdManager.registerConnectionIdInUse(cid);
        });

        // Then
        verify(sender, never()).send(argThat(f -> f instanceof NewConnectionIdFrame), any(), any(Consumer.class));
    }

    void testValidateRetrySourceConnectionId() {
        // Given
        connectionIdManager = new ConnectionIdManager(new byte[8], new byte[8], 6, 2, connectionRegistry, sender, closeCallback, mock(Logger.class));
        byte[] retryCid = new byte[] { 0x06, 0x0f, 0x08, 0x0b };

        // When
        connectionIdManager.registerRetrySourceConnectionId(retryCid);

        // Then
        assertThat(connectionIdManager.validateRetrySourceConnectionId(retryCid)).isTrue();
    }

    @Test
    void whenActiveConnectionIdLimitReachedReceivingRetireShouldNotLeadToNew() {
        // Given
        connectionIdManager.sendNewConnectionId(0);

        // When
        connectionIdManager.sendNewConnectionId(1);
        clearInvocations(sender);
        connectionIdManager.process(new RetireConnectionIdFrame(Version.getDefault(), 0), new byte[3]);

        // Then
        verify(sender, never()).send(any(QuicFrame.class), any(), any(Consumer.class));
    }

    @Test
    void whenConnectionIdAlreadyRetiredReceivingRetireShouldNotLeadToNew() {
        // Given
        connectionIdManager.sendNewConnectionId(0);
        connectionIdManager.process(new RetireConnectionIdFrame(Version.getDefault(), 0), new byte[3]);
        clearInvocations(sender);
        assertThat(connectionIdManager.getActiveConnectionIds()).hasSize(2);  // Because retire triggers new.

        // When
        connectionIdManager.process(new RetireConnectionIdFrame(Version.getDefault(), 0), new byte[3]);

        // Then
        verify(sender, never()).send(any(QuicFrame.class), any(), any(Consumer.class));
    }

    @Test
    void testRegisterInitialPeerCid() {
        // Given
        assertThat(connectionIdManager.getAllPeerConnectionIds().get(0).getConnectionId()).isNotEqualTo(new byte[] { 0x01, 0x02, 0x03, 0x04 });

        // When
        connectionIdManager.registerInitialPeerCid(new byte[] { 0x01, 0x02, 0x03, 0x04 });

        // Then
        assertThat(connectionIdManager.getAllPeerConnectionIds().get(0).getConnectionId()).isEqualTo(new byte[] { 0x01, 0x02, 0x03, 0x04 });
    }
}
