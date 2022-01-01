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

import java.util.Optional;

/**
 * https://tools.ietf.org/html/draft-ietf-quic-tls-29#section2.1
 * "Data is protected using a number of encryption levels:
 *  Initial Keys
 *  Early Data (0-RTT) Keys
 *  Handshake Keys
 *  Application Data (1-RTT) Keys"
 *
 * https://tools.ietf.org/html/draft-ietf-quic-transport-29#section-12.2
 * "...order of increasing encryption levels (Initial, 0-RTT, Handshake, 1-RTT...)"
 */
public enum EncryptionLevel {

    Initial,
    ZeroRTT,
    Handshake,
    App;

    public boolean higher(EncryptionLevel other) {
        return this.ordinal() > other.ordinal();
    }

    public PnSpace relatedPnSpace() {
        switch(this) {
            case ZeroRTT: return PnSpace.App;
            case Initial: return PnSpace.Initial;
            case Handshake: return PnSpace.Handshake;
            case App: return PnSpace.App;
            default: return null;   // Never gets here
        }
    }

    public Optional<EncryptionLevel> next() {
        switch (this) {
            case ZeroRTT: return Optional.of(Initial);
            case Initial: return Optional.of(Handshake);
            case Handshake: return Optional.of(App);
            case App: return Optional.empty();
            default: return Optional.empty();   // Never gets here
        }
    }
}
