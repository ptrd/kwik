/*
 * Copyright © 2023 Peter Doornbosch
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
package net.luminis.quic.path;

import net.luminis.quic.EncryptionLevel;
import net.luminis.quic.TestUtils;
import net.luminis.quic.Version;
import net.luminis.quic.frame.PathChallengeFrame;
import net.luminis.quic.frame.PathResponseFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.send.Sender;
import net.luminis.quic.socket.ClientSocketManager;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

class PathValidatorTest {

    static int newPathPTO;

    PathValidator pathValidator;
    private Sender sender;

    @BeforeAll
    static void computeNewPathPTO() {
        newPathPTO = PathValidator.getPTOforNewPath();
    }

    @BeforeEach
    void initObjectUnderTest() throws Exception {
        sender = mock(Sender.class);
        when(sender.getPto()).thenReturn(newPathPTO);
        ClientSocketManager socketManager = mock(ClientSocketManager.class);
        when(socketManager.bindNewLocalAddress()).thenReturn(TestUtils.getArbitraryLocalAddress());
        pathValidator = new PathValidator(Version.getDefault(), socketManager, sender, mock(Logger.class));
    }

    @Test
    void probeExistingPathSendsPathChallenge() {
        // When
        pathValidator.sendPathChallenge(false);

        // Then
        verify(sender).send(argThat(frame -> frame instanceof PathChallengeFrame), argThat(level -> level == EncryptionLevel.App), any());
    }

    @Test
    void probeNewPathSendsPathChallenge() {
        // When
        pathValidator.sendPathChallenge(true);

        // Then
        verify(sender).sendAlternateAddress(argThat(frame -> frame instanceof PathChallengeFrame), any(InetSocketAddress.class));
    }

    @Test
    void pathValidationSucceeds() throws Exception {
        // Given
        AtomicBoolean result = new AtomicBoolean(false);
        Thread pathValidatorThread = new Thread(() -> {
            result.set(pathValidator.probePath(false));
        });
        pathValidatorThread.start();
        Thread.sleep(10);  // Give thread a change to start, verify does not wait...
        ArgumentCaptor<PathChallengeFrame> frameCapturer = ArgumentCaptor.forClass(PathChallengeFrame.class);
        verify(sender).send(frameCapturer.capture(), any(), any());
        byte[] challenge = frameCapturer.getValue().getData();

        // When
        pathValidator.process(new PathResponseFrame(Version.getDefault(), challenge), null, TestUtils.getArbitraryLocalAddress());

        // Then
        pathValidatorThread.join(100);
        assertThat(result).isTrue();
    }

    @Test
    void pathValidationFailsAfterTimeout() throws Exception {
        // Given
        AtomicReference<String> result = new AtomicReference<>("no result");
        Thread pathValidatorThread = new Thread(() -> {
            if (pathValidator.probePath(false)) {
                result.set("valid");
            } else {
                result.set("failed");
            }
        });
        pathValidatorThread.start();

        // When
        int delta = 10;
        pathValidatorThread.join(newPathPTO + delta);

        // Then
        assertThat(result.get()).isEqualTo("failed");
    }
}