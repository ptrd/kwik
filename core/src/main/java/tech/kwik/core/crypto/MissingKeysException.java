/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.crypto;

import tech.kwik.core.common.EncryptionLevel;

public class MissingKeysException extends Exception {

    public enum Cause {
        MissingKeys,
        DiscardedKeys
    }

    private final EncryptionLevel encryptionLevel;
    private final Cause cause;

    public MissingKeysException(EncryptionLevel encryptionLevel, boolean discarded) {
        super("Missing keys for encryption level " + encryptionLevel
                + (discarded? " (keys discarded)": " (keys not installed)"));
        this.encryptionLevel = encryptionLevel;
        this.cause = discarded ? MissingKeysException.Cause.DiscardedKeys : MissingKeysException.Cause.MissingKeys;
    }

    public Cause getMissingKeysCause() {
        return cause;
    }
}
