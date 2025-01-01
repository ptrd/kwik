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
package net.luminis.quic.impl;

import net.luminis.quic.QuicConnection;

import java.nio.ByteBuffer;


/**
 * Represents a QUIC version.
 */
public class Version {

    public final static Version IETF_draft_27 = new Version(0xff00001b);
    public final static Version IETF_draft_29 = new Version(0xff00001d);
    public final static Version QUIC_version_1 = new Version(0x00000001);
    public final static Version QUIC_version_2 = new Version(0x6b3343cf);

    private int versionId;

    public static Version of(QuicConnection.QuicVersion version) {
        if (version == null) {
            return null;
        }
        switch (version) {
            case V1:
                return QUIC_version_1;
            case V2:
                return QUIC_version_2;
        }
        return null;
    }
    
    public Version(int versionId) {
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

    public boolean isZero() {
        return versionId == 0x00000000;
    }

    public boolean isV1() {
        return versionId == QUIC_version_1.versionId;
    }

    public boolean isV2() {
        return versionId == QUIC_version_2.versionId;
    }

    /**
     * @return   true if version is V1 or V2, false otherwise.
     */
    public boolean isV1V2() {
        return versionId == QUIC_version_1.versionId || versionId == QUIC_version_2.versionId;
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
            case 0x6b3343cf:
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

    public QuicConnection.QuicVersion toQuicVersion() {
        if (versionId == QUIC_version_1.versionId) {
            return QuicConnection.QuicVersion.V1;
        }
        else if (versionId == QUIC_version_2.versionId) {
            return QuicConnection.QuicVersion.V2;
        }
        else {
            return null;
        }
    }
}
