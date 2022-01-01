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

import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.stream.Stream;

public enum Version {

    GoogleQuic_44(0x51303434),
    GoogleQuic_45(0x51303435),
    reserved_1(0x1a2a3a4a),
    IETF_draft_11(0xff00000b),
    IETF_draft_12(0xff00000c),
    IETF_draft_13(0xff00000d),
    IETF_draft_14(0xff00000e),
    IETF_draft_15(0xff00000f),
    IETF_draft_16(0xff000010),
    IETF_draft_17(0xff000011),
    IETF_draft_18(0xff000012),
    IETF_draft_19(0xff000013),
    IETF_draft_20(0xff000014),
    IETF_draft_21(0xff000015),
    IETF_draft_22(0xff000016),
    IETF_draft_23(0xff000017),
    IETF_draft_24(0xff000018),
    IETF_draft_25(0xff000019),
    IETF_draft_26(0xff00001a),
    IETF_draft_27(0xff00001b),
    IETF_draft_28(0xff00001c),
    IETF_draft_29(0xff00001d),
    IETF_draft_30(0xff00001e),
    IETF_draft_31(0xff00001f),
    IETF_draft_32(0xff000020),
    QUIC_version_1(0x00000001);

    private int versionId;

    Version(int versionId) {
        this.versionId = versionId;
    }

    public byte[] getBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
        buffer.putInt(versionId);
        return buffer.array();
    }

    public static Version parse(int input) throws UnknownVersionException {
        Optional<Version> version = Stream.of(Version.values()).filter(candidate -> candidate.versionId == input).findFirst();
        return version.orElseThrow(() -> new UnknownVersionException());
    }

    public static Version getDefault() {
        return QUIC_version_1;
    }

    public boolean atLeast(Version other) {
        // Only for IETF drafts/version
        if (isIetfVersion(this) && isIetfVersion(other)) {
            return this.versionId >= other.versionId;
        }
        else if (isReserved()) {
            // Reserved is considered equivalent to latest
            return true;
        }
        else {
            throw new RuntimeException();
        }
    }

    public boolean before(Version other) {
        // Only for IETF drafts
        if (isIetfVersion(this) && isIetfVersion(other)) {
            return this.versionId < other.versionId;
        }
        else if (isReserved()) {
            // Reserved is considered equivalent to latest
            return false;
        }
        else {
            throw new RuntimeException();
        }
    }

    public boolean isReserved() {
        return this.equals(reserved_1);
    }

    public String getDraftVersion() {
        if (this.name().startsWith("IETF_draft_")) {
            return this.name().substring("IETF_draft_".length());
        }
        else {
            return "";
        }
    }

    private boolean isIetfVersion(Version version) {
        return version.versionId >= IETF_draft_11.versionId && version.versionId <= IETF_draft_32.versionId || version == QUIC_version_1;
    }

    public int getId() {
        return versionId;
    }
}
