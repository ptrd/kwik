/*
 * Copyright © 2019 Peter Doornbosch
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

import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.stream.Stream;

public enum Version {

    GoogleQuic_44(0x51303434),
    GoogleQuic_45(0x51303435),
    IETF_draft_11(0xff00000b),
    IETF_draft_12(0xff00000c),
    IETF_draft_13(0xff00000d),
    IETF_draft_14(0xff00000e),
    IETF_draft_15(0xff00000f),
    IETF_draft_16(0xff000010);

    private int versionId;

    Version(int versionId) {
        this.versionId = versionId;
    }

    byte[] getBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
        buffer.putInt(versionId);
        return buffer.array();
    }

    static Version parse(int input) throws UnknownVersionException {
        Optional<Version> version = Stream.of(Version.values()).filter(candidate -> candidate.versionId == input).findFirst();
        return version.orElseThrow(() -> new UnknownVersionException());
    }

    static Version getDefault() {
        return IETF_draft_16;
    }

    public boolean atLeast(Version other) {
        // Only for IETF drafts
        if (isIetfDraft(this) && isIetfDraft(other)) {
            return this.versionId >= other.versionId;
        }
        else {
            throw new RuntimeException();
        }
    }

    private boolean isIetfDraft(Version version) {
        return version.versionId >= IETF_draft_11.versionId && version.versionId <= IETF_draft_16.versionId;
    }
}
