/*
 * Copyright © 2019, 2020, 2021, 2022, 2023 Peter Doornbosch
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


/**
 * Represents a QUIC version.
 */
public class Version {

    public final static Version IETF_draft_16 = new Version(0xff000010);
    public final static Version IETF_draft_17 = new Version(0xff000011);
    public final static Version IETF_draft_18 = new Version(0xff000012);
    public final static Version IETF_draft_19 = new Version(0xff000013);
    public final static Version IETF_draft_20 = new Version(0xff000014);
    public final static Version IETF_draft_22 = new Version(0xff000016);
    public final static Version IETF_draft_27 = new Version(0xff00001b);
    public final static Version IETF_draft_29 = new Version(0xff00001d);
    public final static Version IETF_draft_30 = new Version(0xff00001e);
    public final static Version IETF_draft_31 = new Version(0xff00001f);
    public final static Version IETF_draft_32 = new Version(0xff000020);
    public final static Version IETF_draft_33 = new Version(0xff000021);
    public final static Version IETF_draft_34 = new Version(0xff000022);
    public final static Version QUIC_version_1 = new Version(0x00000001);
    public final static Version QUIC_version_2 = new Version(0x709a50c4);
    public final static Version reserved_1 = new Version(0x1a2a3a4a);

    private int versionId;

    Version(int versionId) {
        this.versionId = versionId;
    }

    public byte[] getBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
        buffer.putInt(versionId);
        return buffer.array();
    }

    public static Version parse(int input) {
        return new Version(input);
    }

    public static Version getDefault() {
        return QUIC_version_1;
    }

    public boolean isKnown() {
        return isDraftVersion(versionId) || versionId == QUIC_version_1.versionId || versionId == QUIC_version_2.versionId;
    }

    public boolean isZero() {
        return versionId == 0x00000000;
    }

    public boolean isV1() {
        return versionId == 0x00000001;
    }

    public boolean isV2() {
        return versionId == 0x709a50c4;
    }

    /**
     * @return   true if version is V1 or V2, false otherwise.
     */
    public boolean isV1V2() {
        return versionId == 0x00000001 || versionId == 0x709a50c4;
    }

    /**
     * Determines whether this version is equal to or greater then the given version.
     * Should only be called for known versions, both self and the argument!
     * @param other
     * @return
     */
    public boolean atLeast(Version other) {
       return compare(other) >= 0;
    }

    /**
     * Determines whether this version is less than the given version.
     * Should only be called for known versions, both self and the argument!
     * @param other
     * @return
     */
    public boolean before(Version other) {
        return compare(other) < 0;
    }

    private int compare(Version other) {
        if (this.isKnown() && other.isKnown()) {
            if (isDraftVersion(this.versionId) && isDraftVersion(other.versionId)) {
                return Integer.compare(this.versionId, other.versionId);
            } else if (isDraftVersion(this.versionId) && !isDraftVersion(other.versionId)) {
                // draft compare with v1 or v2
                return -1;
            } else if (!isDraftVersion(this.versionId) && isDraftVersion(other.versionId)) {
                // v1 or v2 compare with draft
                return 1;
            } else {
                // v1 compare with v2 or v2 compare with v1
                return Integer.compare(this.versionId, other.versionId);
            }
        } else {
            // Cannot compare unknown version
            throw new IllegalArgumentException();
        }
    }

    private boolean isDraftVersion(int version) {
        return version > 0xff000000 && version <= 0xff000022;
    }

    public boolean isReserved() {
        return this.equals(reserved_1);
    }

    public String getDraftVersion() {
        if (versionId > 0xff000000 && versionId <= 0xff000022) {
            int draft = versionId - 0xff000000;
            return "" + draft;
        }
        else {
            return "";
        }
    }

    public int getId() {
        return versionId;
    }

    @Override
    public String toString() {
        String versionString;
        switch (versionId) {
            case 0x00000001:
                versionString = "v1";
                break;
            case 0x709a50c4:
                versionString = "v2";
                break;
            default:
                if (versionId > 0xff000000 && versionId <= 0xff000022) {
                    versionString = "draft-" + (versionId - 0xff000000);
                }
                else {
                    versionString = "v-" + Integer.toHexString(versionId);
                }
        }
        return versionString;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Version)) return false;

        Version version = (Version) o;

        return versionId == version.versionId;
    }

    @Override
    public int hashCode() {
        return versionId;
    }
}
