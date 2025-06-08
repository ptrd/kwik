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

import tech.kwik.core.frame.NewConnectionIdFrame;
import tech.kwik.core.frame.Padding;
import tech.kwik.core.frame.PathChallengeFrame;
import tech.kwik.core.frame.PathResponseFrame;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.send.SenderImpl;
import tech.kwik.core.socket.ServerConnectionSocketManager;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Comparator;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;


public class PathValidator {

    private static final Random randomGenerator = new SecureRandom();
    private final VersionHolder version;
    private volatile InetSocketAddress currentAddress;
    private final SenderImpl sender;
    private final Logger logger;
    private final ServerConnectionSocketManager socketManager;
    private final Clock clock;
    private final Map<Long, PathValidation> pathValidationsByChallenge;
    private final Map<InetSocketAddress, PathValidation> pathValidationsByAddress;
    private final ScheduledExecutorService executor;
    private volatile long highestReceivedPacketNumber;
    private volatile Instant currentAddressLastUsed;

    public PathValidator(VersionHolder version, InetSocketAddress clientAddress, SenderImpl sender, Logger logger, ServerConnectionSocketManager socketManager) {
        this(Executors.newSingleThreadScheduledExecutor(), version, clientAddress, sender, logger, socketManager, Clock.systemUTC());
    }

    public PathValidator(ScheduledExecutorService executor, VersionHolder version, InetSocketAddress clientAddress, SenderImpl sender, Logger logger, ServerConnectionSocketManager socketManager, Clock clock) {
        this.version = version;
        currentAddress = clientAddress;
        this.sender = sender;
        this.logger = logger;
        this.socketManager = socketManager;
        this.clock = clock;
        pathValidationsByChallenge = new ConcurrentHashMap<>();
        pathValidationsByAddress = new ConcurrentHashMap<>();
        this.executor = executor;

        pathValidationsByAddress.put(clientAddress, PathValidation.preValidated(clientAddress, clock.instant()));
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
            else if (! pathValidationInProgress(packetSourceAddress)) {
                // https://www.rfc-editor.org/rfc/rfc9000.html#section-9
                // "An endpoint MUST perform path validation (Section 8.2) if it detects any change to a peer's address, "
                logger.info(String.format("Potential address migration? %s -> %s; starting path validation", currentAddress, packetSourceAddress));
                startValidation(packet, packetSourceAddress);
            }
        }
        else {
            currentAddressLastUsed = clock.instant();
        }
    }

    private void startValidation(QuicPacket packet, InetSocketAddress packetSourceAddress) {
        PathValidation validation = new PathValidation(packetSourceAddress, isProbingPacket(packet), clock.instant());
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

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.4
        // "Endpoints SHOULD abandon path validation based on a timer."
        if (clock.instant().isAfter(validation.startedAt().plusMillis((long) (3 * initialPto * 1.05f)))) {
            logger.info("Path validation failed for " + validation.getAddressToValidate() + " after " + validation.getChallengeRepeatCount() + " attempts and timeout of " + (3 * initialPto) + "ms");
            remove(validation);
        }
        else {
            byte[] challenge = generateChallenge();
            pathValidationsByChallenge.put(convertToLong(challenge), validation);
            PathChallengeFrame pathChallengeFrame = new PathChallengeFrame(version.getVersion(), challenge);
            sender.sendAlternateAddress(pathChallengeFrame, validation.getAddressToValidate());
            validation.incrementChallengeRepeatCount();

            // And schedule the next check
            executor.schedule(() -> {
                if (validation.isInProgress()) {
                    doValidation(validation);
                }
            }, delay, java.util.concurrent.TimeUnit.MILLISECONDS);
        }
    }

    private void remove(PathValidation validation) {
        pathValidationsByAddress.remove(validation.getAddressToValidate());
        pathValidationsByChallenge.values().removeIf(v -> v == validation);
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
        socketManager.changeClientAddress(newAddress);
        PathValidation validation = pathValidationsByAddress.get(currentAddress);
        if (validation != null) {
            validation.setAddressLastUsed(currentAddressLastUsed);
        }
        currentAddress = newAddress;
        currentAddressLastUsed = null;
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
            PathValidation pathValidation = pathValidationsByChallenge.remove(challenge);
            pathValidation.setValidated();
            InetSocketAddress validatedAddress = pathValidation.getAddressToValidate();
            logger.info("Path validated: " + validatedAddress);
            if (! pathValidation.isStartedByProbingPacket()) {
                logger.info("Immediately migrating connection to validated address: " + validatedAddress);
                migrateConnection(validatedAddress);
            }
        }
        else {
            logger.info("Received unexpected path response: " + pathResponseFrame);
        }
    }

    public boolean isValidated(InetSocketAddress newAddress) {
        PathValidation validation = pathValidationsByAddress.get(newAddress);
        return validation != null && validation.isValidated(clock.instant());
    }
}
