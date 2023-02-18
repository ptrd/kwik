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
import net.luminis.quic.frame.PathChallengeFrame;
import net.luminis.quic.frame.PathResponseFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.QuicPacket;
import net.luminis.quic.send.Sender;
import net.luminis.quic.socket.ClientSocketManager;
import net.luminis.quic.Version;

import java.net.InetSocketAddress;
import java.net.SocketException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Handles the path validation process. See
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-path-validation.
 */
public class PathValidator {

    private final Version quicVersion;
    private final Logger log;
    private final ClientSocketManager socketManager;
    private final Sender sender;
    private final SecureRandom randomGenerator;
    private volatile byte[] challengePayload;
    private CountDownLatch pathValidatedCondition;

    public static int getPTOforNewPath() {
        int kInitialRtt = 333;
        int smoothedRtt = kInitialRtt;
        int rttvar = kInitialRtt / 2;
        return smoothedRtt + 4 * rttvar;
    }

    public PathValidator(Version quicVersion, ClientSocketManager socketManager, Sender sender, Logger log) {
        this.quicVersion = quicVersion;
        this.log = log;
        this.socketManager = socketManager;
        this.sender = sender;
        randomGenerator = new SecureRandom();
    }

    public boolean probePath(boolean newPath) {
        pathValidatedCondition = new CountDownLatch(1);
        sendPathChallenge(newPath);
        try {
            // https://www.rfc-editor.org/rfc/rfc9000.html#name-failed-path-validation
            // "Endpoints SHOULD abandon path validation based on a timer. (...)  A value of three times the larger of the
            //  current PTO or the PTO for the new path (using kInitialRtt, as defined in [QUIC-RECOVERY]) is RECOMMENDED."
            int timeOut = Integer.max(getPTOforNewPath(), sender.getPto());
            return pathValidatedCondition.await(timeOut, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            return false;
        }
    }

    public void process(PathResponseFrame pathResponseFrame, QuicPacket packet, InetSocketAddress clientAddress) {
        if (challengePayload != null) {
            // https://www.rfc-editor.org/rfc/rfc9000.html#name-successful-path-validation
            // "Path validation succeeds when a PATH_RESPONSE frame is received that contains the data that was sent
            //  in a previous PATH_CHALLENGE frame. A PATH_RESPONSE frame received on any network path validates the
            //  path on which the PATH_CHALLENGE was sent."
            if (Arrays.equals(pathResponseFrame.getData(), challengePayload)) {
                log.info("Path validation succeeded; got path challenge response on port " + clientAddress.getPort());
                pathValidatedCondition.countDown();
                challengePayload = null;
            }
            else {
                log.error("Incorrect path validation (wrong data)");
            }
        }
        else {
            log.error("Path response received, but no path validation in progress");
        }
    }

    void sendPathChallenge(boolean newPath) {
        try {
            challengePayload = new byte[8];
            randomGenerator.nextBytes(challengePayload);
            PathChallengeFrame pathChallengeFrame = new PathChallengeFrame(quicVersion, challengePayload);
            if (newPath) {
                log.info("Sending path challenge from new local address");
                InetSocketAddress newLocalAddress = socketManager.bindNewLocalAddress();
                sender.sendAlternateAddress(pathChallengeFrame, newLocalAddress);
            }
            else {
                log.info("Sending path challenge from existing local address");
                sender.send(pathChallengeFrame, EncryptionLevel.App, null);
                sender.flush();
            }
        } catch (SocketException e) {
            // Fairly impossible, as we created a socket on an ephemeral port
            log.error("Changing local address failed", e);
        }
    }
}
