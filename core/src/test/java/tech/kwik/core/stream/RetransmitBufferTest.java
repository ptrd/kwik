/*
 * Copyright © 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.stream;


import tech.kwik.core.frame.StreamFrame;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RetransmitBufferTest {

    private RetransmitBuffer retransmitBuffer;

    @BeforeEach
    void setUpObjectUnderTest() {
        retransmitBuffer = new RetransmitBuffer();
    }

    @Test
    void initiallyBufferShouldBeEmpty() {
        // When

        // Then
        assertThat(retransmitBuffer.hasDataToRetransmit()).isFalse();
        assertThat(retransmitBuffer.getFrameToRetransmit(1250)).isNull();
    }

    @Test
    void whenDataIsAddedBufferShouldProvideStreamFrame() {
        // Given
        retransmitBuffer.add(new StreamFrame(0, 7000, generateData(1212), true));

        // When
        StreamFrame retransmit = retransmitBuffer.getFrameToRetransmit(1250);

        // Then
        assertThat(retransmit).isNotNull();
        assertThat(retransmit.getOffset()).isEqualTo(7000);
        assertThat(retransmit.getStreamData().length).isEqualTo(1212);
        assertThat(verifyData(retransmit.getStreamData())).isTrue();
    }

    @Test
    void whenLessDataIsRequestedThanAvailableBufferShouldProvideStreamFrameWithRightLength() {
        // Given
        retransmitBuffer.add(new StreamFrame(0, 7000, generateData(1212), true));

        // When
        StreamFrame retransmit = retransmitBuffer.getFrameToRetransmit(800);

        // Then
        assertThat(retransmit).isNotNull();
        assertThat(retransmit.getOffset()).isEqualTo(7000);
        assertThat(retransmit.getFrameLength()).isEqualTo(800);
        assertThat(verifyData(retransmit.getStreamData())).isTrue();
    }

    @Test
    void whenLessDataIsRequestedThanAvailableBufferShouldEventuallyProvideAllData() {
        // Given
        retransmitBuffer.add(new StreamFrame(0, 7000, generateData(1212), true));

        // When
        StreamFrame retransmit1 = retransmitBuffer.getFrameToRetransmit(800);
        StreamFrame retransmit2 = retransmitBuffer.getFrameToRetransmit(400);
        StreamFrame retransmit3 = retransmitBuffer.getFrameToRetransmit(200);

        byte[] allData = new byte[1212];
        System.arraycopy(retransmit1.getStreamData(), 0, allData, 0, retransmit1.getStreamData().length);
        System.arraycopy(retransmit2.getStreamData(), 0, allData, retransmit1.getStreamData().length, retransmit2.getStreamData().length);
        System.arraycopy(retransmit3.getStreamData(), 0, allData, retransmit1.getStreamData().length + retransmit2.getStreamData().length, retransmit3.getStreamData().length);

        // Then
        assertThat(retransmit1).isNotNull();
        assertThat(retransmit1.getOffset()).isEqualTo(7000);
        assertThat(retransmit1.getFrameLength()).isEqualTo(800);
        assertThat(retransmit1.isFinal()).isFalse();
        assertThat(retransmit2).isNotNull();
        assertThat(retransmit2.getOffset()).isEqualTo(7000 + retransmit1.getLength());
        assertThat(retransmit2.getFrameLength()).isEqualTo(400);
        assertThat(retransmit2.isFinal()).isFalse();
        assertThat(retransmit3.getOffset()).isEqualTo(7000 + retransmit1.getLength() + retransmit2.getLength());
        assertThat(retransmit3).isNotNull();
        assertThat(retransmit3.isFinal()).isTrue();
        assertThat(verifyData(allData)).isTrue();
    }

    @Test
    void whenDataIsAddedBufferShouldIndicateThatDataIsAvailable() {
        // Given
        retransmitBuffer.add(new StreamFrame(0, 7000, generateData(1212), true));

        // When

        // Then
        assertThat(retransmitBuffer.hasDataToRetransmit()).isTrue();
    }

    @Test
    void whenDataIsAddedAndRetransmittedBufferShouldIndicateThatDataIsNotAvailable() {
        // Given
        retransmitBuffer.add(new StreamFrame(0, 7000, generateData(1212), true));
        retransmitBuffer.getFrameToRetransmit(1500);

        // When

        // Then
        assertThat(retransmitBuffer.hasDataToRetransmit()).isFalse();
    }

    private byte[] generateData(int length) {
        byte[] data = new byte[length];
        for (int i = 0; i < length; i++) {
            data[i] = (byte) i;
        }
        return data;
    }

    private boolean verifyData(byte[] data) {
        for (int i = 0; i < data.length; i++) {
            if (data[i] != (byte) (i)) {
                return false;
            }
        }
        return true;
    }
}