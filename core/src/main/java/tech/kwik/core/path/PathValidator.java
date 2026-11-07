/*
 * Copyright © 2025, 2026 Peter Doornbosch
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

import tech.kwik.core.cid.ConnectionIdProvider;
import tech.kwik.core.frame.NewConnectionIdFrame;
import tech.kwik.core.frame.Padding;
import tech.kwik.core.frame.PathChallengeFrame;
import tech.kwik.core.frame.PathResponseFrame;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.send.SendOptions;
import tech.kwik.core.send.SenderImpl;
import tech.kwik.core.socket.ServerConnectionSocketManager;
import tech.kwik.core.util.OneShotRateLimiter;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;


public class PathValidator {

    private static final Random randomGenerator = new SecureRandom();
    // Size of a datagram containing a path challenge that is expanded with padding.
    static final int PADDED_PATH_CHALLENGE_DATAGRAM_SIZE = 1200;
    // Upper bound for the size of a datagram containing a path challenge without padding: a short header packet with
    // flags (1), max length destination connection id (20), max length packet number (4), path challenge frame (9)
    // and AEAD tag (16).
    static final int MAX_UNPADDED_PATH_CHALLENGE_DATAGRAM_SIZE = 1 + 20 + 4 + 9 + 16;
    private final VersionHolder version;
    private volatile InetSocketAddress currentAddress;
    private final SenderImpl sender;
    private final ConnectionIdProvider connectionIdProvider;
    private final Logger logger;
    private final ServerConnectionSocketManager socketManager;
    private final Clock clock;
    private final Map<Long, SentChallenge> pathValidationsByChallenge;
    private final Map<InetSocketAddress, PathValidation> pathValidationsByAddress;
    private final ScheduledExecutorService executor;
    private volatile long highestReceivedPacketNumber;
    private volatile Instant currentAddressLastUsed;
    private final boolean peerUsesNonZeroLengthConnectionIDs;
    private OneShotRateLimiter logOncePerAddressRateLimiter;

    public PathValidator(VersionHolder version, InetSocketAddress clientAddress, SenderImpl sender, ServerConnectionSocketManager socketManager, ConnectionIdProvider connectionIdProvider, Logger logger) {
        this(Executors.newSingleThreadScheduledExecutor(), version, clientAddress, sender, socketManager, Clock.systemUTC(), connectionIdProvider, logger);
    }

    public PathValidator(ScheduledExecutorService executor, VersionHolder version, InetSocketAddress clientAddress, SenderImpl sender,
                         ServerConnectionSocketManager socketManager, Clock clock, ConnectionIdProvider connectionIdProvider, Logger logger) {
        this.version = version;
        currentAddress = clientAddress;
        this.sender = sender;
        this.connectionIdProvider = connectionIdProvider;
        this.logger = logger;
        this.socketManager = socketManager;
        this.clock = clock;
        pathValidationsByChallenge = new ConcurrentHashMap<>();
        pathValidationsByAddress = new ConcurrentHashMap<>();
        this.executor = executor;
        peerUsesNonZeroLengthConnectionIDs = !connectionIdProvider.peerUsesZeroLengthConnectionId();

        pathValidationsByAddress.put(clientAddress, PathValidation.preValidated(clientAddress, clock.instant()));
        logOncePerAddressRateLimiter = new OneShotRateLimiter(2);
    }

    public void checkSourceAddress(QuicPacket packet, PacketMetaData metaData) {
        highestReceivedPacketNumber = Long.max(highestReceivedPacketNumber, packet.getPacketNumber());

        InetSocketAddress packetSourceAddress = metaData.sourceAddress();

        if (!packetSourceAddress.equals(currentAddress)) {

            if (isValidated(packetSourceAddress)) {
                // https://www.rfc-editor.org/rfc/rfc9000.html#section-9.3
                // "Receiving a packet from a new peer address containing a non-probing frame indicates that the peer has migrated to that address."
                // "An endpoint only changes the address to which it sends packets in response to the highest-numbered non-probing packet."
                if (!isProbingPacket(packet) && packet.getPacketNumber() == highestReceivedPacketNumber) {
                    logger.info("Receiving non-probing packet on new (validated) path; migrating connection to " + packetSourceAddress);
                    migrateConnection(packetSourceAddress);
                }
            }
            else if (pathValidationInProgress(packetSourceAddress)) {
                PathValidation validation = pathValidationsByAddress.get(packetSourceAddress);
                if (validation != null) {
                    validation.addBytesReceived(metaData.getDatagramSize());
                }
            }
            else {
                // https://www.rfc-editor.org/rfc/rfc9000.html#section-9.3
                // "If the recipient has no unused connection IDs from the peer, it will not be able to send anything on
                //  the new path until the peer provides one; ..."
                // https://www.rfc-editor.org/rfc/rfc9000.html#section-9.5
                // "An endpoint that exhausts available connection IDs cannot probe new paths or initiate migration, nor
                //  can it respond to probes or attempts by its peer to migrate."
                if (! hasUnusedPeerConnectionIDs() && peerUsesNonZeroLengthConnectionIDs) {
                    logOncePerAddressRateLimiter.execute(packetSourceAddress, () ->
                            logger.info(String.format("Potential address migration? %s -> %s, but cannot start path validation due to lack of unused peer connection IDs",
                                    currentAddress, packetSourceAddress)));
                }
                else {
                    // https://www.rfc-editor.org/rfc/rfc9000.html#section-9
                    // "An endpoint MUST perform path validation (Section 8.2) if it detects any change to a peer's address, "
                    logger.info(String.format("Potential address migration? %s -> %s; starting path validation", currentAddress, packetSourceAddress));
                    startValidation(packet, metaData, packetSourceAddress);
                }
            }
        }
        else {
            currentAddressLastUsed = clock.instant();
        }
    }

    private boolean hasUnusedPeerConnectionIDs() {
        return connectionIdProvider.unusedPeerConnectionIdAvailable();
    }

    private void startValidation(QuicPacket packet, PacketMetaData metaData, InetSocketAddress packetSourceAddress) {
        PathValidation validation = new PathValidation(packetSourceAddress, isProbingPacket(packet), clock.instant());
        validation.addBytesReceived(metaData.getDatagramSize());
        pathValidationsByAddress.put(packetSourceAddress, validation);

        doValidation(validation);

        purgeOldValidations();
    }

    private void doValidation(PathValidation validation) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.1
        // "An endpoint SHOULD NOT probe a new path with packets containing a PATH_CHALLENGE frame more frequently
        //  than it would send an Initial packet. "
        int initialPto = 1000;
        int delay = initialPto * (int) (Math.pow(2, validation.getChallengeRepeatCount()));
        long timeout = (long) (3 * initialPto * 1.05f);

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.4
        // "Endpoints SHOULD abandon path validation based on a timer."
        if (clock.instant().isAfter(validation.startedAt().plusMillis(timeout))) {
            logger.info("Path validation failed for " + validation.getAddressToValidate() + " after " + validation.getChallengeRepeatCount() + " attempts and timeout of " + (3 * initialPto) + "ms");
            remove(validation);
        }
        else {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.1
            // "An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame to at least the smallest allowed
            //  maximum datagram size of 1200 bytes, unless the anti-amplification limit for the path does not permit
            //  sending a datagram of this size."
            // Padding must not consume all credit: enough must be left to send (unpadded) path challenges in the
            // remaining attempts, in case this one gets lost.
            long credit = validation.getAntiAmplificationCredit();
            long reserved = (long) remainingAttempts(validation, delay, timeout) * MAX_UNPADDED_PATH_CHALLENGE_DATAGRAM_SIZE;
            if (credit - PADDED_PATH_CHALLENGE_DATAGRAM_SIZE >= reserved) {
                sendPathChallenge(validation, SendOptions.getDefault(), PADDED_PATH_CHALLENGE_DATAGRAM_SIZE, true);
            }
            else if (credit >= MAX_UNPADDED_PATH_CHALLENGE_DATAGRAM_SIZE) {
                sendPathChallenge(validation, SendOptions.noPadding(), MAX_UNPADDED_PATH_CHALLENGE_DATAGRAM_SIZE, false);
            }
            else {
                logger.info("Anti-amplification limit prevents sending path challenge to " + validation.getAddressToValidate());
            }

            // And schedule the next check
            executor.schedule(() -> {
                if (validation.isInProgress()) {
                    doValidation(validation);
                }
            }, delay, java.util.concurrent.TimeUnit.MILLISECONDS);
        }
    }

    /**
     * Computes how many more path challenges will be sent (after the current one) before the validation times out,
     * given the delay until the next attempt and the doubling of the delay with each attempt.
     */
    private int remainingAttempts(PathValidation validation, long delay, long timeout) {
        long elapsed = Duration.between(validation.startedAt(), clock.instant()).toMillis();
        int remaining = 0;
        while (elapsed + delay <= timeout) {
            remaining++;
            elapsed += delay;
            delay *= 2;
        }
        return remaining;
    }

    private void sendPathChallenge(PathValidation validation, SendOptions sendOptions, int datagramSize, boolean padded) {
        byte[] challenge = generateChallenge();
        pathValidationsByChallenge.put(convertToLong(challenge), new SentChallenge(validation, padded));
        PathChallengeFrame pathChallengeFrame = new PathChallengeFrame(version.getVersion(), challenge);
        sender.sendAlternateAddress(pathChallengeFrame, validation.getAddressToValidate(), sendOptions);
        validation.addBytesSent(datagramSize);
        validation.incrementChallengeRepeatCount();
    }

    private void remove(PathValidation validation) {
        pathValidationsByAddress.remove(validation.getAddressToValidate());
        pathValidationsByChallenge.values().removeIf(sent -> sent.validation == validation);
    }

    private void purgeOldValidations() {
        pathValidationsByAddress.values().stream()
                .sorted(Comparator.reverseOrder())
                .skip(10)
                .forEach(this::remove);
    }

    private boolean pathValidationInProgress(InetSocketAddress address) {
        PathValidation validation = pathValidationsByAddress.get(address);
        return validation != null && validation.isInProgress();
    }

    private void migrateConnection(InetSocketAddress newAddress) {
        InetSocketAddress previousAddress = currentAddress;
        socketManager.changeClientAddress(newAddress);

        PathValidation validation = pathValidationsByAddress.get(previousAddress);
        if (validation != null) {
            validation.setAddressLastUsed(currentAddressLastUsed);
        }

        currentAddress = newAddress;
        currentAddressLastUsed = null;

        // let connection id manager know that the previous address is no longer in use, so it can retire the connection id associated with it
        connectionIdProvider.addressNoLongerInUse(previousAddress);
    }

    private byte[] generateChallenge() {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.1
        // "The endpoint MUST use unpredictable data in every PATH_CHALLENGE frame so that it can associate the peer's
        //  response with the corresponding PATH_CHALLENGE."
        byte[] data = new byte[8];
        randomGenerator.nextBytes(data);
        return data;
    }

    private Long convertToLong(byte[] challenge) {
        assert challenge.length == 8;
        return ByteBuffer.wrap(challenge).getLong();
    }

    static boolean isProbingPacket(QuicPacket packet) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-9.1
        // "A packet containing only probing frames is a "probing packet", and a packet containing any other frame is a "non-probing packet"."
        return packet.getFrames().stream().allMatch(PathValidator::isProbingFrame);
    }

    static boolean isProbingFrame(QuicFrame frame) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-9.1
        // "PATH_CHALLENGE, PATH_RESPONSE, NEW_CONNECTION_ID, and PADDING frames are "probing frames", and all other frames are "non-probing frames".
        return frame instanceof PathChallengeFrame ||
                frame instanceof PathResponseFrame ||
                frame instanceof NewConnectionIdFrame ||
                frame instanceof Padding;
    }

    public void checkPathResponse(PathResponseFrame pathResponseFrame, PacketMetaData metaData) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.3
        // "Path validation succeeds when a PATH_RESPONSE frame is received that contains the data that was sent in a
        //  previous PATH_CHALLENGE frame. A PATH_RESPONSE frame received on any network path validates the path on
        //  which the PATH_CHALLENGE was sent."
        Long challenge = convertToLong(pathResponseFrame.getData());
        if (pathValidationsByChallenge.containsKey(challenge)) {
            SentChallenge sentChallenge = pathValidationsByChallenge.remove(challenge);
            PathValidation pathValidation = sentChallenge.validation;
            pathValidation.setValidated(sentChallenge.padded);
            InetSocketAddress validatedAddress = pathValidation.getAddressToValidate();
            logger.info("Path validated: " + validatedAddress + (sentChallenge.padded? " (with full size packet)": " (with small packet)"));
            if (! pathValidation.isStartedByProbingPacket()) {
                logger.info("Immediately migrating connection to validated address: " + validatedAddress);
                migrateConnection(validatedAddress);
            }
        }
        else {
            logger.info("Received unexpected path response: " + pathResponseFrame);
        }
    }

    /**
     * @return  true if the given address is validated or being validated, which implies a connection ID of the peer
     * has been assigned to it, so packets can be sent to it
     */
    public boolean isValidatedOrInProgress(InetSocketAddress address) {
        return isValidated(address) || pathValidationInProgress(address);
    }

    public boolean isValidated(InetSocketAddress newAddress) {
        PathValidation validation = pathValidationsByAddress.get(newAddress);
        return validation != null && validation.isValidated(clock.instant());
    }

    public boolean isValidatedWithFullSizePacket(InetSocketAddress address) {
        PathValidation validation = pathValidationsByAddress.get(address);
        return validation != null && validation.isValidated(clock.instant()) && validation.isValidatedWithFullSizePacket();
    }

    private static class SentChallenge {
        final PathValidation validation;
        // Whether the datagram containing the path challenge was expanded to 1200 bytes.
        final boolean padded;

        SentChallenge(PathValidation validation, boolean padded) {
            this.validation = validation;
            this.padded = padded;
        }
    }
}
