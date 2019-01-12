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
