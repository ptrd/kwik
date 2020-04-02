/*
 * Copyright © 2019, 2020 Peter Doornbosch
 *
 * This file is part of Kwik, a QUIC client Java library
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

public enum EncryptionLevel {

    ZeroRTT,
    Initial,
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
}
