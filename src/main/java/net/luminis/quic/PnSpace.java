/*
 * Copyright © 2019, 2020, 2021, 2022 Peter Doornbosch
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
package net.luminis.quic;

/**
 * Packet numbers are divided into three spaces in QUIC.
 *
 * See https://www.rfc-editor.org/rfc/rfc9000.html#name-packet-numbers:
 * Initial space: All Initial packets (Section 17.2.2) are in this space.
 * Handshake space: All Handshake packets (Section 17.2.4) are in this space.
 * Application data space: All 0-RTT (Section 17.2.3) and 1-RTT (Section 17.3.1) packets are in this space.
 *
 */
public enum PnSpace {

    Initial,
    Handshake,
    App;

    public EncryptionLevel relatedEncryptionLevel() {
        switch(this) {
            case Initial: return EncryptionLevel.Initial;
            case Handshake: return EncryptionLevel.Handshake;
            case App: return EncryptionLevel.App;
            default: return null;   // Never gets here
        }
    }
}
