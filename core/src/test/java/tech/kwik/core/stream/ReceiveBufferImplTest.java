package tech.kwik.core.stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;

class ReceiveBufferImplTest {

    private ReceiveBufferImpl receiveBuffer;
    private static final int MAX_COMBINED_FRAME_SIZE = 2500;

    @BeforeEach
    void setUpObjectUnderTest() {
        receiveBuffer = new ReceiveBufferImpl(null, MAX_COMBINED_FRAME_SIZE);
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
    void emtpyFinalFrameEndsStream() {
        // Given
        receiveBuffer.add(new DataFrame(0, 1000, false));

        // When
        receiveBuffer.add(new DataFrame(1000, 0, true));

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

    @Test
    void outOfOrderBufferedDataShouldBeMeasured() {
        // Given
        receiveBuffer.add(new DataFrame(200, 100));

        // Then
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(100);
    }

    @Test
    void outOfOrderBufferedDataMeasurementIsDecreasedWhenBecomingContiguous() {
        // Given
        receiveBuffer.add(new DataFrame(200, 100));
        receiveBuffer.add(new DataFrame(500, 300));
        long initialDataBuffered = receiveBuffer.bufferedOutOfOrderData();

        // When
        receiveBuffer.add(new DataFrame(0, 200));

        // Then
        assertThat(initialDataBuffered).isEqualTo(400);
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(300);
    }

    @Test
    void outOfOrderBufferedDataMeasurementDropsToZeroWhenAllGapsFilled() {
        // Given
        receiveBuffer.add(new DataFrame(200, 120));
        receiveBuffer.add(new DataFrame(800, 100));
        receiveBuffer.add(new DataFrame(600, 50));
        receiveBuffer.add(new DataFrame(400, 100));

        // When
        receiveBuffer.add(new DataFrame(500, 100));
        receiveBuffer.add(new DataFrame(320, 80));
        receiveBuffer.add(new DataFrame(0, 140));
        receiveBuffer.add(new DataFrame(140, 60));
        receiveBuffer.add(new DataFrame(650, 150));

        // Then
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(0);
    }

    @Test
    void duplicatedFramesAreCombinedToReduceMemoryUsage() {
        // Given
        receiveBuffer.add(new DataFrame(200, 120));

        // When
        receiveBuffer.add(new DataFrame(200, 120));

        // Then
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(120);
        checkDataCanBeReadAfterAdding(320, new DataFrame(0, 200));
    }

    @Test
    void duplicatedFramesAreCombinedToReduceMemoryUsage2() {
        // Given
        receiveBuffer.add(new DataFrame(100, 100));
        receiveBuffer.add(new DataFrame(200, 120));

        // When
        receiveBuffer.add(new DataFrame(200, 120));

        // Then
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(220);
        checkDataCanBeReadAfterAdding(320, new DataFrame(0, 100));
    }

    @Test
    void duplicatedFramesAreCombinedToReduceMemoryUsage3() {
        // Given
        receiveBuffer.add(new DataFrame(200, 120));
        receiveBuffer.add(new DataFrame(320, 100));

        // When
        receiveBuffer.add(new DataFrame(200, 120));

        // Then
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(220);
        checkDataCanBeReadAfterAdding(420, new DataFrame(0, 200));
    }

    @Test
    void whenDuplicatedFramesWithDifferentFinalFlagAreCombinedFinalIsStillSet() {
        // Given
        receiveBuffer.add(new DataFrame(20, 100));

        // When
        receiveBuffer.add(new DataFrame(20, 100, true));
        receiveBuffer.add(new DataFrame(0, 120));

        // Then
        assertThat(receiveBuffer.allDataReceived()).isTrue();
    }

    @Test
    void containingFramesAreCombinedToReduceMemoryUsage() {
        // Given                        200..299
        receiveBuffer.add(new DataFrame(200, 100));

        // When                         220..259
        receiveBuffer.add(new DataFrame(220, 60));

        // Then
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(100);
        checkDataCanBeReadAfterAdding(300, new DataFrame(0, 200));
    }

    @Test
    void containingFramesAreCombinedToReduceMemoryUsage2() {
        // Given                        220..259
        receiveBuffer.add(new DataFrame(220, 60));

        // When                          200..299
        receiveBuffer.add(new DataFrame(200, 100));

        // Then
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(100);
        checkDataCanBeReadAfterAdding(300, new DataFrame(0, 200));
    }

    @Test
    void overlappingFramesAreCombinedToReduceMemoryUsage1() {
        // Given                        100..189
        receiveBuffer.add(new DataFrame(100, 90));

        // When                         150..249
        receiveBuffer.add(new DataFrame(150, 100));

        // Then
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(150);
        checkDataCanBeReadAfterAdding(250, new DataFrame(0, 100));
    }

    @Test
    void overlappingFramesAreCombinedToReduceMemoryUsage2() {
        // Given                        150..249
        receiveBuffer.add(new DataFrame(150, 100));

        // When                         100..189
        receiveBuffer.add(new DataFrame(100, 90));

        // Then
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(150);
        checkDataCanBeReadAfterAdding(250, new DataFrame(0, 100));
    }

    @Test
    void overlappingFramesAreCombinedToReduceMemoryUsage3() {
        // Given                        50..99 100..199 300..399 400..449
        receiveBuffer.add(new DataFrame(100, 100));
        receiveBuffer.add(new DataFrame(300, 100));
        receiveBuffer.add(new DataFrame(50, 50));
        receiveBuffer.add(new DataFrame(400, 50));

        // When
        receiveBuffer.add(new DataFrame(170, 200));

        // Then
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(400);
        checkDataCanBeReadAfterAdding(450, new DataFrame(0, 50));
    }

    @Test
    void multipleOverlappingFramesAreCombinedToReduceMemoryUsage1() {
        // Given          50..99 100..199 200..299 300..349
        receiveBuffer.add(new DataFrame(50, 50));
        receiveBuffer.add(new DataFrame(100, 100));
        receiveBuffer.add(new DataFrame(200, 100));
        receiveBuffer.add(new DataFrame(300, 50));

        // When           80..329
        receiveBuffer.add(new DataFrame(80, 250));

        // Then
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(300);
        checkDataCanBeReadAfterAdding(350, new DataFrame(0, 50));
    }

    @Test
    void multipleOverlappingFramesAreCombinedToReduceMemoryUsage2() {
        // Given          100..199 200..299 300..349
        receiveBuffer.add(new DataFrame(100, 100));
        receiveBuffer.add(new DataFrame(200, 100));
        receiveBuffer.add(new DataFrame(300, 50));

        // When           80..329
        receiveBuffer.add(new DataFrame(80, 250));

        // Then           80..349
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(270);
        checkDataCanBeReadAfterAdding(350, new DataFrame(0, 100));
    }

    @Test
    void multipleOverlappingFramesAreCombinedToReduceMemoryUsage3() {
        // Given          20..60 100..199 200..299 300..349
        receiveBuffer.add(new DataFrame(20, 40));
        receiveBuffer.add(new DataFrame(100, 100));
        receiveBuffer.add(new DataFrame(200, 100));
        receiveBuffer.add(new DataFrame(300, 50));

        // When           80..329
        receiveBuffer.add(new DataFrame(80, 250));

        // Then           20..60 80..349
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(310);
        checkDataCanBeReadAfterAdding(350, new DataFrame(0, 100));
    }

    @Test
    void multipleOverlappingFramesWithGapsAreCombinedToReduceMemoryUsage1() {
        // Given          50..99 110..189 200..289 300..349
        receiveBuffer.add(new DataFrame(50, 50));
        receiveBuffer.add(new DataFrame(110, 80));
        receiveBuffer.add(new DataFrame(200, 90));
        receiveBuffer.add(new DataFrame(310, 40));

        // When           80..329
        receiveBuffer.add(new DataFrame(80, 250));

        // Then
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(300);
        checkDataCanBeReadAfterAdding(350, new DataFrame(0, 50));
    }

    @Test
    void multipleOverlappingFramesAreCombinedToReduceMemoryUsage() {
        // Given
        receiveBuffer.add(new DataFrame(100, 100));
        receiveBuffer.add(new DataFrame(200, 100));
        receiveBuffer.add(new DataFrame(50, 50));
        receiveBuffer.add(new DataFrame(300, 50));

        // When
        receiveBuffer.add(new DataFrame(80, 200));

        // Then
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(300);
        checkDataCanBeReadAfterAdding(350, new DataFrame(0, 50));
    }

    @Test
    void frameShouldNotBeCombinedWithBeforeWhenLargerThanMax() {
        // Given                        1000..1999 2200..3199 3500..4499
        receiveBuffer.add(new DataFrame(1000, 1000));
        receiveBuffer.add(new DataFrame(2200, 1000));
        receiveBuffer.add(new DataFrame(3500, 1000));

        // When                         1900..2299
        receiveBuffer.add(new DataFrame(1900, 400));
        //                              3100..3599
        receiveBuffer.add(new DataFrame(3100, 600));

        // Then
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        assertThat(receiveBuffer.maxOutOfOrderFrameSize()).isLessThanOrEqualTo(MAX_COMBINED_FRAME_SIZE);
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(3500);
        checkDataCanBeReadAfterAdding(4500, new DataFrame(0, 1000));
    }

    @Test
    void frameShouldNotBeCombinedWithAfterWhenLargerThanMax() {
        // Given                        1000..1999 2200..3199 3500..4499
        receiveBuffer.add(new DataFrame(1000, 1000));
        receiveBuffer.add(new DataFrame(2200, 1000));
        receiveBuffer.add(new DataFrame(3500, 1000));

        //                              3100..3599
        receiveBuffer.add(new DataFrame(3100, 600));
        // When                         1900..2299
        receiveBuffer.add(new DataFrame(1900, 400));

        // Then
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        assertThat(receiveBuffer.maxOutOfOrderFrameSize()).isLessThanOrEqualTo(MAX_COMBINED_FRAME_SIZE);
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(3500);
        checkDataCanBeReadAfterAdding(4500, new DataFrame(0, 1000));
    }

    @Test
    void whenShrunkFrameOverlapsWithFormerNextThatHoweverBecomesBefore() {
        // Given                        1000..3499
        receiveBuffer.add(new DataFrame(1000, 2500));
        //                              2501..3500
        receiveBuffer.add(new DataFrame(2501, 1000));

        // When                          2502..3501
        receiveBuffer.add(new DataFrame(2502, 1000));

        // Then                          1000..3501
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        assertThat(receiveBuffer.maxOutOfOrderFrameSize()).isLessThanOrEqualTo(MAX_COMBINED_FRAME_SIZE);
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(2502);
        checkDataCanBeReadAfterAdding(3502, new DataFrame(0, 1000));
    }

    @Test
    void addZeroSizeFrame() {
        // Given
        receiveBuffer.add(new DataFrame(100, 100));

        // When
        receiveBuffer.add(new DataFrame(234, 0));
        receiveBuffer.add(new DataFrame(235, 0));
        receiveBuffer.add(new DataFrame(236, 0));
        receiveBuffer.add(new DataFrame(235, 1));

        // Then
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(101);
        assertThat(receiveBuffer.countOutOfOrderFrames()).isEqualTo(2);
        checkDataCanBeReadAfterAdding(100, new DataFrame(0, 100));
    }

    @Test
    void whenFramesAreAddedToContiguousStreamOverlapIsRemoved() {
        // Given                        0..249  500..749
        receiveBuffer.add(new DataFrame(0, 250));
        receiveBuffer.add(new DataFrame(500, 250));

        // When                          200..599
        receiveBuffer.add(new DataFrame(200, 400));

        // Then
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        checkDataCanBeReadAfterAdding(750);
    }

    @Test
    void testRandomStreamElementAdditions() {
        Random random = new Random();
        int streamEnd = 100_000;
        int added = 0;
        String bufferContentBefore = "";
        DataFrame frame = null;
        try {
            while (receiveBuffer.bytesAvailable() < streamEnd) {
                bufferContentBefore = receiveBuffer.toDebugString(5000);
                int offset = random.nextInt(streamEnd);
                int length = random.nextInt(1000);
                frame = new DataFrame(offset, length);
                added++;
                receiveBuffer.add(frame);
                assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
            }
            System.out.println("Tested random stream element additions with " + added + " frames");
        }
        catch (AssertionError e) {
            System.out.println("Assert failed while adding " + frame + " to " + bufferContentBefore + " resulting in " + receiveBuffer.toDebugString(5000));
            throw e;
        }
    }

    @Test
    void testProperContainingFrame() {
        // Given
        DataFrame frame1 = new DataFrame(100, 100);
        DataFrame frame2 = new DataFrame(130, 50);

        // Then
        assertThat(ReceiveBufferImpl.contains(frame1, frame2)).isTrue();
        assertThat(ReceiveBufferImpl.contains(frame2, frame1)).isFalse();
    }

    @Test
    void testEqualFramesContainOneAnother() {
        // Given
        DataFrame frame1 = new DataFrame(100, 100);
        DataFrame frame2 = new DataFrame(100, 100);

        // Then
        assertThat(ReceiveBufferImpl.contains(frame1, frame2)).isTrue();
        assertThat(ReceiveBufferImpl.contains(frame2, frame1)).isTrue();
    }

    @Test
    void testContainedFramesSameStart() {
        // Given
        DataFrame frame1 = new DataFrame(100, 100);
        DataFrame frame2 = new DataFrame(100, 50);

        // Then
        assertThat(ReceiveBufferImpl.contains(frame1, frame2)).isTrue();
        assertThat(ReceiveBufferImpl.contains(frame2, frame1)).isFalse();
    }

    @Test
    void testContainedFramesSameEnd() {
        // Given
        DataFrame frame1 = new DataFrame(100, 100);
        DataFrame frame2 = new DataFrame(150, 50);

        // Then
        assertThat(ReceiveBufferImpl.contains(frame1, frame2)).isTrue();
        assertThat(ReceiveBufferImpl.contains(frame2, frame1)).isFalse();
    }

    @Test
    void combineEqualFrames() {
        // Given
        DataFrame frame1 = new DataFrame(100, 100);
        DataFrame frame2 = new DataFrame(100, 100);

        // When
        StreamElement combined = ReceiveBufferImpl.combine(frame1, frame2);

        // Then
        assertThat(combined.equals(frame1) || combined.equals(frame2)).isTrue();
        assertThat(ReceiveBufferImpl.combinedLength(frame1, frame2)).isEqualTo(combined.getLength());
    }

    @Test
    void combineContainingFrames1() {
        // Given
        DataFrame frame1 = new DataFrame(100, 100);
        DataFrame frame2 = new DataFrame(110, 30);

        // When
        StreamElement combined = ReceiveBufferImpl.combine(frame1, frame2);

        // Then
        assertThat(combined.getOffset()).isEqualTo(100);
        assertThat(combined.getLength()).isEqualTo(100);
        assertThat(ReceiveBufferImpl.combinedLength(frame1, frame2)).isEqualTo(combined.getLength());
        checkData(ByteBuffer.wrap(combined.getStreamData()));
    }

    @Test
    void combineContainingFrames2() {
        // Given
        DataFrame frame1 = new DataFrame(100, 100);
        DataFrame frame2 = new DataFrame(100, 130);

        // When
        StreamElement combined = ReceiveBufferImpl.combine(frame1, frame2);

        // Then
        assertThat(combined.getOffset()).isEqualTo(100);
        assertThat(combined.getLength()).isEqualTo(130);
        assertThat(ReceiveBufferImpl.combinedLength(frame1, frame2)).isEqualTo(combined.getLength());
        checkData(ByteBuffer.wrap(combined.getStreamData()));
    }

    @Test
    void combineContainingFrames3() {
        // Given
        DataFrame frame1 = new DataFrame(100, 100);
        DataFrame frame2 = new DataFrame(110, 90);

        // When
        StreamElement combined = ReceiveBufferImpl.combine(frame1, frame2);

        // Then
        assertThat(combined.getOffset()).isEqualTo(100);
        assertThat(combined.getLength()).isEqualTo(100);
        assertThat(ReceiveBufferImpl.combinedLength(frame1, frame2)).isEqualTo(combined.getLength());
        checkData(ByteBuffer.wrap(combined.getStreamData()));
    }

    @Test
    void combineOverlappingFrames() {
        // Given
        DataFrame frame1 = new DataFrame(100, 100);
        DataFrame frame2 = new DataFrame(190, 30);

        // When
        StreamElement combined = ReceiveBufferImpl.combine(frame1, frame2);

        // Then
        assertThat(combined.getOffset()).isEqualTo(100);
        assertThat(combined.getLength()).isEqualTo(120);
        assertThat(ReceiveBufferImpl.combinedLength(frame1, frame2)).isEqualTo(combined.getLength());
        checkData(ByteBuffer.wrap(combined.getStreamData()));
    }

    private void checkData(ByteBuffer buffer) {
        for (int i = 0; i < buffer.position(); i++) {
            assertThat(buffer.get(i)).isEqualTo((byte) i);
        }
    }

    private void checkDataCanBeReadAfterAdding(int length, DataFrame... dataFrames) {
        System.out.println("test result: " + receiveBuffer.toDebugString());
        Arrays.stream(dataFrames).forEach(f -> receiveBuffer.add(f));
        ByteBuffer readBytes = ByteBuffer.allocate(length);
        int bytesRead = receiveBuffer.read(readBytes);
        assertThat(bytesRead).isEqualTo(length);
        checkData(readBytes);
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

        @Override
        public String toString() {
            return "" + offset + ".." + (offset + data.length - 1);
        }
    }
}