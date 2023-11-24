package net.luminis.quic.stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;

class ReceiveBufferImplTest {

    private ReceiveBufferImpl receiveBuffer;

    @BeforeEach
    void setUpObjectUnderTest() {
        receiveBuffer = new ReceiveBufferImpl();
    }

    @Test
    void readFromEmptyStreamReturnsNothing() {
        // When
        int bytesRead = receiveBuffer.read(ByteBuffer.allocate(100));

        // Then
        assertThat(bytesRead).isEqualTo(0);
        assertThat(receiveBuffer.bytesAvailable()).isEqualTo(0);
    }

    @Test
    void whenFramesAreReceivedButNotTheStartOfTheStreamThenNoDataIsAvailable() {
        // When
        receiveBuffer.add(new DataFrame(100, 900));

        // Then
        assertThat(receiveBuffer.bytesAvailable()).isEqualTo(0);
        assertThat(receiveBuffer.read(ByteBuffer.allocate(4000))).isEqualTo(0);
    }

    @Test
    void whenStartOfStreamIsReceivedThenDataIsAvailable() {
        // Given
        receiveBuffer.add(new DataFrame(100, 500));

        // When
        receiveBuffer.add(new DataFrame(0, 100));

        // Then
        assertThat(receiveBuffer.bytesAvailable()).isEqualTo(600);
        ByteBuffer buffer = ByteBuffer.allocate(1009);
        assertThat(receiveBuffer.read(buffer)).isEqualTo(600);
        assertThat(buffer.position()).isEqualTo(600);
        assertThat(buffer.get(99)).isEqualTo((byte) 99);
        assertThat(buffer.get(100)).isEqualTo((byte) 100);
    }

    @Test
    void attemptToReadZeroBytesIsOkAndJustReturnsZeroBytes() {
        // Given
        receiveBuffer.add(new DataFrame(0, 500));

        // When
        int bytesRead = receiveBuffer.read(ByteBuffer.allocate(0));

        // Then
        assertThat(bytesRead).isEqualTo(0);
    }

    @Test
    void overlappingFramesDoNotDuplicateData() {
        // Given
        receiveBuffer.add(new DataFrame(100, 500));

        // When
        receiveBuffer.add(new DataFrame(50, 200));
        receiveBuffer.add(new DataFrame(0, 70));

        // Then
        assertThat(receiveBuffer.bytesAvailable()).isEqualTo(600);
        ByteBuffer buffer = ByteBuffer.allocate(1234);
        assertThat(receiveBuffer.read(buffer)).isEqualTo(600);
        assertThat(buffer.position()).isEqualTo(600);
        checkData(buffer);
    }

    @Test
    void receivingOldDataShouldNotInfluenceBytesAvailable() {
        receiveBuffer.add(new DataFrame(0, 12));
        receiveBuffer.add(new DataFrame(12, 9));
        receiveBuffer.add(new DataFrame(9, 9));

        assertThat(receiveBuffer.bytesAvailable()).isEqualTo(12 + 9);
    }

    @Test
    void streamDataIsAlwaysInOrderWhenReceivingDuplicateDataWithWeirdOffsets() {
        // Given
        receiveBuffer.add(new DataFrame(10, 10));
        receiveBuffer.add(new DataFrame(11, 8));
        receiveBuffer.add(new DataFrame(12, 9));
        receiveBuffer.add(new DataFrame(9, 9));
        receiveBuffer.add(new DataFrame(8, 11));
        receiveBuffer.add(new DataFrame(7, 7));
        receiveBuffer.add(new DataFrame(6, 1));
        receiveBuffer.add(new DataFrame(1, 1));
        receiveBuffer.add(new DataFrame(0, 2));
        receiveBuffer.add(new DataFrame(1, 2));
        receiveBuffer.add(new DataFrame(2, 3));
        receiveBuffer.add(new DataFrame(3, 5));
        receiveBuffer.add(new DataFrame(0, 7));

        // Then
        assertThat(receiveBuffer.bytesAvailable()).isEqualTo(12 + 9);
        ByteBuffer buffer = ByteBuffer.allocate(100);
        assertThat(receiveBuffer.read(buffer)).isEqualTo(12 + 9);
        checkData(buffer);
    }

    @Test
    void readingDataUpdatesTheReadOffset() {
        // Given
        receiveBuffer.add(new DataFrame(70, 30));
        receiveBuffer.add(new DataFrame(0, 70));

        // When
        receiveBuffer.read(ByteBuffer.allocate(85));

        // Then
        assertThat(receiveBuffer.readOffset()).isEqualTo(85);
    }

    @Test
    void finalFrameReceivedDoesNotMeanAllDataIsReceived() {
        // When
        receiveBuffer.add(new DataFrame(100, 900, true));

        // Then
        assertThat(receiveBuffer.allDataReceived()).isFalse();
    }

    @Test
    void onlyWhenAllDataIncludingFinalFrameIsReceivedAllDataReceivedIsTrue() {
        // Given
        receiveBuffer.add(new DataFrame(100, 900, true));

        // When
        receiveBuffer.add(new DataFrame(0, 900));

        // Then
        assertThat(receiveBuffer.allDataReceived()).isTrue();
    }

    @Test
    void whenAllDataIsReceivedDoesNotMeansAllDataIsRead() {
        // Given
        receiveBuffer.add(new DataFrame(0, 100, true));

        // When
        receiveBuffer.read(ByteBuffer.allocate(50));

        // Then
        assertThat(receiveBuffer.allDataReceived()).isTrue();
        assertThat(receiveBuffer.allRead()).isFalse();
    }

    @Test
    void whenAllDataIsReadThenAllDataIsRead() {
        // Given
        receiveBuffer.add(new DataFrame(0, 100, true));

        // When
        receiveBuffer.read(ByteBuffer.allocate(50));
        receiveBuffer.read(ByteBuffer.allocate(50));

        // Then
        assertThat(receiveBuffer.allRead()).isTrue();
    }

    @Test
    void whenAllDataIsReadThenReadReturnsMinusOne() {
        // Given
        receiveBuffer.add(new DataFrame(0, 100, true));
        receiveBuffer.read(ByteBuffer.allocate(100));

        // When
        int readResult = receiveBuffer.read(ByteBuffer.allocate(50));

        // Then
        assertThat(readResult).isEqualTo(-1);
    }

    private void checkData(ByteBuffer buffer) {
        for (int i = 0; i < buffer.position(); i++) {
            assertThat(buffer.get(i)).isEqualTo((byte) i);
        }
    }

    private static class DataFrame implements StreamElement {

        private final long offset;
        private final byte[] data;
        private final int length;
        private final boolean isFinal;

        public DataFrame(long offset, int length, boolean isFinal) {
            this.offset = offset;
            this.data = new byte[length];
            for (int i = 0; i < length; i++) {
                data[i] = (byte) ((offset + i) % 256);
            }
            this.length = length;
            this.isFinal = isFinal;
        }

        public DataFrame(long offset, int length) {
            this(offset, length, false);
        }

        @Override
        public long getOffset() {
            return offset;
        }

        @Override
        public int getLength() {
            return length;
        }

        @Override
        public byte[] getStreamData() {
            return data;
        }

        @Override
        public long getUpToOffset() {
            return offset + length;
        }

        @Override
        public boolean isFinal() {
            return isFinal;
        }

        @Override
        public int compareTo(StreamElement other) {
            if (this.offset != other.getOffset()) {
                return Long.compare(this.offset, other.getOffset());
            }
            else {
                return Integer.compare(this.length, other.getLength());
            }
        }
    }
}