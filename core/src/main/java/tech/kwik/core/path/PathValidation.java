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

import java.net.InetSocketAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;

public class PathValidation implements Comparable<PathValidation> {

    private static final int UNUSED_ADDRESS_MAX_VALIDATION_TIME = 5 * 60;

    public enum Status {InProgress, Validated, Failed}

    private final InetSocketAddress addressToValidate;
    private final boolean startedByProbingPacket;
    private final Instant startedAt;
    private Status status = Status.InProgress;
    private Instant addressLastUsed;

    private int challengeRepeatCount = 0;

    public PathValidation(InetSocketAddress addressToValidate, boolean startedByProbingPacket, Instant start) {
        this.addressToValidate = addressToValidate;
        this.startedByProbingPacket = startedByProbingPacket;
        this.startedAt = start;
    }

    public static PathValidation preValidated(InetSocketAddress validatedAddress, Instant validatedAt) {
        return new PathValidation(validatedAddress, validatedAt);
    }

    private PathValidation(InetSocketAddress validatedAddress, Instant validatedAt) {
        this.addressToValidate = validatedAddress;
        this.startedAt = validatedAt;
        this.startedByProbingPacket = false;
        this.status = Status.Validated;
    }

    @Override
    public int compareTo(PathValidation other) {
        return Comparator.comparing(PathValidation::startTime).compare(this, other);
    }

    private Instant startTime() {
        return startedAt;
    }

    public InetSocketAddress getAddressToValidate() {
        return addressToValidate;
    }

    public int getChallengeRepeatCount() {
        return challengeRepeatCount;
    }

    public void incrementChallengeRepeatCount() {
        this.challengeRepeatCount++;
    }

    public boolean isStartedByProbingPacket() {
        return startedByProbingPacket;
    }

    public boolean isInProgress() {
        return status == Status.InProgress;
    }

    public boolean isValidated(Instant now) {
        return status == Status.Validated &&
                validatedRecently(now);
    }

    // https://www.rfc-editor.org/rfc/rfc9000.html#section-9.3
    // "An endpoint MAY skip validation of a peer address if that address has been seen recently."
    private boolean validatedRecently(Instant now) {
        return addressLastUsed == null?
                Duration.between(startedAt, now).toSeconds() < UNUSED_ADDRESS_MAX_VALIDATION_TIME :
                Duration.between(addressLastUsed, now).toSeconds() < UNUSED_ADDRESS_MAX_VALIDATION_TIME;
    }

    public void setAddressLastUsed(Instant addressLastUsed) {
        this.addressLastUsed = addressLastUsed;
    }

    public void setValidated() {
        status = Status.Validated;
    }

    public Instant startedAt() {
        return startedAt;
    }
}
