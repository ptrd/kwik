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

public class PathValidation {

    public enum Status {InProgress, Validated, Failed}

    private final InetSocketAddress addressToValidate;
    private final boolean startedByProbingPacket;
    private Status status = Status.InProgress;

    public PathValidation(InetSocketAddress addressToValidate, boolean startedByProbingPacket) {
        this.addressToValidate = addressToValidate;
        this.startedByProbingPacket = startedByProbingPacket;
    }

    public InetSocketAddress getAddressToValidate() {
        return addressToValidate;
    }

    public boolean isStartedByProbingPacket() {
        return startedByProbingPacket;
    }

    public boolean isInProgress() {
        return status == Status.InProgress;
    }

    public boolean isValidated() {
        return status == Status.Validated;
    }

    public void setValidated() {
        status = Status.Validated;
    }
}
