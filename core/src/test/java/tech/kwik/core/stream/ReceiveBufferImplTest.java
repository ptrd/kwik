/*
 * Copyright © 2023, 2024, 2025, 2026 Peter Doornbosch
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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.core.QuicConstants;
import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.impl.TransportError;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class ReceiveBufferImplTest {

    private ReceiveBufferImpl receiveBuffer;
    private static final int MAX_COMBINED_FRAME_SIZE = 2500;
    private static final int BUFFER_SIZE = 1024 * 1024;

    @BeforeEach
    void setUpObjectUnderTest() {
        receiveBuffer = new ReceiveBufferImpl(BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
    }

    // region reading data
    @Test
    void readFromEmptyStreamReturnsNothing() {
        // When
        int bytesRead = receiveBuffer.read(ByteBuffer.allocate(100));

        // Then
        assertThat(bytesRead).isEqualTo(0);
        assertThat(receiveBuffer.bytesAvailable()).isEqualTo(0);
    }

    @Test
    void whenFramesAreReceivedButNotTheStartOfTheStreamThenNoDataIsAvailable() throws Exception {
        // When
        receiveBuffer.add(new DataFrame(100, 900));

        // Then
        assertThat(receiveBuffer.bytesAvailable()).isEqualTo(0);
        assertThat(receiveBuffer.read(ByteBuffer.allocate(4000))).isEqualTo(0);
    }

    @Test
    void whenStartOfStreamIsReceivedThenDataIsAvailable() throws Exception {
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
    void attemptToReadZeroBytesIsOkAndJustReturnsZeroBytes() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 500));

        // When
        int bytesRead = receiveBuffer.read(ByteBuffer.allocate(0));

        // Then
        assertThat(bytesRead).isEqualTo(0);
    }

    @Test
    void overlappingFramesDoNotDuplicateData() throws Exception {
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
    void receivingOldDataShouldNotInfluenceBytesAvailable() throws Exception {
        receiveBuffer.add(new DataFrame(0, 12));
        receiveBuffer.add(new DataFrame(12, 9));
        receiveBuffer.add(new DataFrame(9, 9));

        assertThat(receiveBuffer.bytesAvailable()).isEqualTo(12 + 9);
    }

    @Test
    void streamDataIsAlwaysInOrderWhenReceivingDuplicateDataWithWeirdOffsets() throws Exception {
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
    void readingDataUpdatesTheReadOffset() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(70, 30));
        receiveBuffer.add(new DataFrame(0, 70));

        // When
        receiveBuffer.read(ByteBuffer.allocate(85));

        // Then
        assertThat(receiveBuffer.readOffset()).isEqualTo(85);
    }

    @Test
    void emtpyNonFinalFrameChangesNothing() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 50));
        receiveBuffer.add(new DataFrame(50, 50));
        receiveBuffer.add(new DataFrame(555, 100));

        // When
        boolean newData = receiveBuffer.add(new DataFrame(100, 0, false));

        // Then
        assertThat(newData).isFalse();
        assertThat(receiveBuffer.bytesAvailable()).isEqualTo(100);
        assertThat(receiveBuffer.readOffset()).isEqualTo(0);
    }
    // endregion

    // region normal stream completion
    @Test
    void finalFrameReceivedDoesNotMeanAllDataIsReceived() throws Exception {
        // When
        receiveBuffer.add(new DataFrame(100, 900, true));

        // Then
        assertThat(receiveBuffer.allDataReceived()).isFalse();
    }

    @Test
    void onlyWhenAllDataIncludingFinalFrameIsReceivedAllDataReceivedIsTrue() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(100, 900, true));

        // When
        receiveBuffer.add(new DataFrame(0, 900));

        // Then
        assertThat(receiveBuffer.allDataReceived()).isTrue();
    }

    @Test
    void emtpyFinalFrameEndsStream() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 1000, false));

        // When
        receiveBuffer.add(new DataFrame(1000, 0, true));

        // Then
        assertThat(receiveBuffer.allDataReceived()).isTrue();
    }

    @Test
    void whenAllDataIsReceivedDoesNotMeansAllDataIsRead() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 100, true));

        // When
        receiveBuffer.read(ByteBuffer.allocate(50));

        // Then
        assertThat(receiveBuffer.allDataReceived()).isTrue();
        assertThat(receiveBuffer.allRead()).isFalse();
    }

    @Test
    void whenAllDataIsReadThenAllDataIsRead() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 100, true));

        // When
        receiveBuffer.read(ByteBuffer.allocate(50));
        receiveBuffer.read(ByteBuffer.allocate(50));

        // Then
        assertThat(receiveBuffer.allRead()).isTrue();
    }

    @Test
    void whenAllDataIsReadThenReadReturnsMinusOne() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 100, true));
        receiveBuffer.read(ByteBuffer.allocate(100));

        // When
        int readResult = receiveBuffer.read(ByteBuffer.allocate(50));

        // Then
        assertThat(readResult).isEqualTo(-1);
    }
    // endregion

    // region abnormal stream completion
    @Test
    void whenAllDataDiscardedNothingCanBeRead() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 100));

        // When
        receiveBuffer.discardAllData();

        // Then
        assertThat(receiveBuffer.read(ByteBuffer.allocate(100))).isEqualTo(-1);
    }

    @Test
    void whenAllDataDiscardedThenNoDataIsAvailable() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 100));

        // When
        receiveBuffer.discardAllData();

        // Then
        assertThat(receiveBuffer.bytesAvailable()).isEqualTo(0);
    }

    @Test
    void whenAllDataDiscardedThenAllDataIsReceived() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 100));

        // When
        receiveBuffer.discardAllData();

        // Then
        assertThat(receiveBuffer.allDataReceived()).isTrue();
    }

    @Test
    void whenAllDataDiscardedThenAllDataIsRead() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 100));

        // When
        receiveBuffer.discardAllData();

        // Then
        assertThat(receiveBuffer.allRead()).isTrue();
    }

    @Test
    void whenDataIsDiscardedAfterPartialReadStatusMethodsRemainConsistent() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 100));
        receiveBuffer.read(ByteBuffer.allocate(50));

        // When
        receiveBuffer.discardAllData();

        // Then
        // Note: discardAllData() leaves the internal contiguousUpToOffset stale, but the status methods short-circuit
        // on the discarded flag, so they must still report a consistent "nothing left, all done" state.
        assertThat(receiveBuffer.bytesAvailable()).isEqualTo(0);
        assertThat(receiveBuffer.allRead()).isTrue();
        assertThat(receiveBuffer.allDataReceived()).isTrue();
        assertThat(receiveBuffer.read(ByteBuffer.allocate(100))).isEqualTo(-1);
    }

    @Test
    void whenDataIsDiscardedReadOffsetReflectsBytesActuallyRead() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 100));
        receiveBuffer.read(ByteBuffer.allocate(50));

        // When
        receiveBuffer.discardAllData();

        // Then
        assertThat(receiveBuffer.readOffset()).isEqualTo(50);
    }

    @Test
    void whenContiguousFrameArrivesAfterDiscardNoDataBecomesReadable() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 100));
        receiveBuffer.discardAllData();

        // When
        receiveBuffer.add(new DataFrame(100, 50));  // late frame, contiguous with the discarded data

        // Then
        assertThat(receiveBuffer.bytesAvailable()).isEqualTo(0);
        assertThat(receiveBuffer.allRead()).isTrue();
        assertThat(receiveBuffer.read(ByteBuffer.allocate(100))).isEqualTo(-1);
    }
    // endregion

    // region discard data beyond offset
    @Test
    void whenDiscardDataBeyondIsSetDataBeyondTheOffsetIsNotAvailable() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 1000));

        // When
        receiveBuffer.discardDataBeyond(400);

        // Then
        assertThat(receiveBuffer.bytesAvailable()).isEqualTo(400);
    }

    @Test
    void readReturnsDataOnlyUpToDiscardOffset() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 1000));
        receiveBuffer.discardDataBeyond(400);

        // When
        ByteBuffer buffer = ByteBuffer.allocate(1000);
        int bytesRead = receiveBuffer.read(buffer);

        // Then
        assertThat(bytesRead).isEqualTo(400);
        assertThat(buffer.position()).isEqualTo(400);
        checkData(buffer);
    }

    @Test
    void whenAllDataUpToDiscardOffsetIsReadThenAllRead() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 1000));
        receiveBuffer.discardDataBeyond(400);

        // When
        receiveBuffer.read(ByteBuffer.allocate(400));

        // Then
        assertThat(receiveBuffer.allRead()).isTrue();
    }

    @Test
    void whenReadReachesDiscardOffsetThenReadReturnsMinusOne() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 1000));
        receiveBuffer.discardDataBeyond(400);
        receiveBuffer.read(ByteBuffer.allocate(400));

        // When
        int readResult = receiveBuffer.read(ByteBuffer.allocate(100));

        // Then
        assertThat(readResult).isEqualTo(-1);
    }

    @Test
    void whenAllDataUpToDiscardOffsetIsReceivedThenAllDataReceived() throws Exception {
        // Given
        receiveBuffer.discardDataBeyond(400);

        // When
        receiveBuffer.add(new DataFrame(0, 400));

        // Then
        // All data up to the discard offset has been received and nothing beyond it will ever be delivered,
        // so the stream has received all the data it ever will.
        assertThat(receiveBuffer.allDataReceived()).isTrue();
    }

    @Test
    void whenDiscardOffsetIsSetAfterDataIsReceivedThenAllDataReceived() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 1000));

        // When
        receiveBuffer.discardDataBeyond(400);

        // Then
        // All data up to the discard offset has been received and nothing beyond it will ever be delivered,
        // so the stream has received all the data it ever will.
        assertThat(receiveBuffer.allDataReceived()).isTrue();
    }

    @Test
    void frameEntirelyBeyondDiscardOffsetIsNotAdded() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 400));
        receiveBuffer.discardDataBeyond(400);

        // When
        boolean newReadableData = receiveBuffer.add(new DataFrame(400, 600));

        // Then
        assertThat(newReadableData).isFalse();
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(0);
        assertThat(receiveBuffer.bytesAvailable()).isEqualTo(400);
    }

    @Test
    void outOfOrderFrameEntirelyBeyondDiscardOffsetIsNotAdded() throws Exception {
        // Given
        receiveBuffer.discardDataBeyond(400);

        // When
        boolean newReadableData = receiveBuffer.add(new DataFrame(500, 100));

        // Then
        assertThat(newReadableData).isFalse();
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(0);
    }

    @Test
    void frameStraddlingDiscardOffsetIsAvailableUpToTheOffset() throws Exception {
        // Given
        receiveBuffer.discardDataBeyond(400);

        // When                          0..999, straddling the discard offset
        receiveBuffer.add(new DataFrame(0, 1000));

        // Then
        assertThat(receiveBuffer.bytesAvailable()).isEqualTo(400);
        ByteBuffer buffer = ByteBuffer.allocate(1000);
        assertThat(receiveBuffer.read(buffer)).isEqualTo(400);
        checkData(buffer);
        assertThat(receiveBuffer.allRead()).isTrue();
    }

    @Test
    void dataBeforeDiscardOffsetSpreadOverMultipleFramesIsFullyAvailable() throws Exception {
        // Given
        receiveBuffer.discardDataBeyond(400);

        // When
        receiveBuffer.add(new DataFrame(0, 300));
        receiveBuffer.add(new DataFrame(300, 700));   // straddles the discard offset

        // Then
        assertThat(receiveBuffer.bytesAvailable()).isEqualTo(400);
        ByteBuffer buffer = ByteBuffer.allocate(1000);
        assertThat(receiveBuffer.read(buffer)).isEqualTo(400);
        checkData(buffer);
        assertThat(receiveBuffer.allRead()).isTrue();
    }

    @Test
    void discardOffsetCanOnlyDecrease() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 1000));
        receiveBuffer.discardDataBeyond(400);

        // When  (a higher offset must be ignored: a reset can only lower the reliable size)
        receiveBuffer.discardDataBeyond(700);

        // Then
        assertThat(receiveBuffer.bytesAvailable()).isEqualTo(400);
        assertThat(receiveBuffer.read(ByteBuffer.allocate(1000))).isEqualTo(400);
    }

    @Test
    void loweringDiscardOffsetBelowReadOffsetIsHandledGracefully() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 1000));
        receiveBuffer.read(ByteBuffer.allocate(500));   // read offset is now 500

        // When  (e.g. a late reset lowers the reliable size below what was already read)
        receiveBuffer.discardDataBeyond(300);

        // Then  (no negative values, nothing more to read)
        assertThat(receiveBuffer.bytesAvailable()).isEqualTo(0);
        assertThat(receiveBuffer.allRead()).isTrue();
        assertThat(receiveBuffer.read(ByteBuffer.allocate(100))).isEqualTo(-1);
    }

    @Test
    void readingExactlyUpToDiscardOffsetInChunksDoesNotReadBeyondIt() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 1000));
        receiveBuffer.discardDataBeyond(400);

        // When
        int firstRead = receiveBuffer.read(ByteBuffer.allocate(250));
        int secondRead = receiveBuffer.read(ByteBuffer.allocate(250));
        int thirdRead = receiveBuffer.read(ByteBuffer.allocate(250));

        // Then
        assertThat(firstRead).isEqualTo(250);
        assertThat(secondRead).isEqualTo(150);   // capped at the discard offset (400)
        assertThat(thirdRead).isEqualTo(-1);      // all read
        assertThat(receiveBuffer.readOffset()).isEqualTo(400);
    }

    @Test
    void whenAllDataUpToDiscardOffsetIsReadThenFrameStraddlingDiscardOffsetIsRemoved() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 1000));
        receiveBuffer.discardDataBeyond(400);   // discard offset is larger than read offset (0)

        // When
        int bytesRead = receiveBuffer.read(ByteBuffer.allocate(1000));
        int readResult = receiveBuffer.read(ByteBuffer.allocate(1000));

        // Then
        assertThat(bytesRead).isEqualTo(400);
        assertThat(readResult).isEqualTo(-1);
        // The frame (0..999) is only read up to the discard offset (400), but as nothing beyond it will ever be read,
        // it should be removed, just like a frame that is read up to its end.
        assertThat(receiveBuffer.estimatedMemoryUsage()).isEqualTo(0);
    }

    @Test
    void whenDiscardDataBeyondIsNotCalledAllDataRemainsAvailable() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 1000));

        // Then
        assertThat(receiveBuffer.bytesAvailable()).isEqualTo(1000);
        assertThat(receiveBuffer.read(ByteBuffer.allocate(1000))).isEqualTo(1000);
    }

    @Test
    void retransmittedFramesStraddlingDiscardOffsetDoNotCauseOverlap() throws Exception {
        // Given
        receiveBuffer.discardDataBeyond(100);
        receiveBuffer.add(new DataFrame(0, 150));

        // When  (retransmissions of 50..149, which straddles the discard offset)
        for (int i = 0; i < 10; i++) {
            receiveBuffer.add(new DataFrame(50, 100));
        }

        // Then
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        ByteBuffer buffer = ByteBuffer.allocate(1000);
        assertThat(receiveBuffer.read(buffer)).isEqualTo(100);
        checkData(buffer);
        assertThat(receiveBuffer.allRead()).isTrue();
    }

    @Test
    void whenReadExactlyUpToDiscardOffsetNoMemoryIsUsedAnymore() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 1000));
        receiveBuffer.add(new DataFrame(1000, 1000));
        receiveBuffer.add(new DataFrame(2000, 1000));
        receiveBuffer.discardDataBeyond(500);

        // When
        int bytesRead = receiveBuffer.read(ByteBuffer.allocate(500));

        // Then
        assertThat(bytesRead).isEqualTo(500);
        assertThat(receiveBuffer.allRead()).isTrue();
        assertThat(receiveBuffer.estimatedMemoryUsage()).isEqualTo(0);
    }

    @Test
    void outOfOrderFrameStraddlingDiscardOffsetOnlyBuffersDataUpToDiscardOffset() throws Exception {
        // Given
        receiveBuffer.discardDataBeyond(1000);

        // When
        receiveBuffer.add(new DataFrame(500, 1200));

        // Then
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(500);
    }
    // endregion

    // region out-of-order data measurement
    @Test
    void outOfOrderBufferedDataShouldBeMeasured() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(200, 100));

        // Then
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(100);
    }

    @Test
    void outOfOrderBufferedDataMeasurementIsDecreasedWhenBecomingContiguous() throws Exception {
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
    void outOfOrderBufferedDataMeasurementDropsToZeroWhenAllGapsFilled() throws Exception {
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
    void outOfOrderBufferedDataMeasurementIsZeroAfterPartialRetransmitOfContiguousData() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 100));

        // When
        receiveBuffer.add(new DataFrame(50, 100));

        // Then
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(0);
    }

    @Test
    void outOfOrderBufferedDataMeasurementIsZeroAfterDuplicateOfContiguousData() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 100));

        // When
        receiveBuffer.add(new DataFrame(0, 50));

        // Then
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(0);
    }

    @Test
    void outOfOrderBufferedDataMeasurementIsZeroWhenContiguousFrameCoversOutOfOrderFrame() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(100, 20));

        // When
        receiveBuffer.add(new DataFrame(0, 150));

        // Then
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(0);
        checkDataCanBeReadAfterAdding(150);
    }

    @Test
    void outOfOrderBufferedDataMeasurementIsZeroWhenContiguousFramePartiallyOverlapsOutOfOrderFrame() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(100, 100));

        // When
        receiveBuffer.add(new DataFrame(0, 150));

        // Then
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(0);
        checkDataCanBeReadAfterAdding(200);
    }
    // endregion

    // region memory usage estimation
    @Test
    void estimatedMemoryUsageOfEmptyBufferIsZero() {
        assertThat(receiveBuffer.estimatedMemoryUsage()).isEqualTo(0);
    }

    @Test
    void estimatedMemoryUsageIncludesContiguousDataAndFrameOverhead() throws Exception {
        // When
        receiveBuffer.add(new DataFrame(0, 100));
        receiveBuffer.add(new DataFrame(100, 200));

        // Then
        assertThat(receiveBuffer.estimatedMemoryUsage()).isEqualTo(300 + 2 * ReceiveBufferImpl.FRAME_OVERHEAD);
    }

    @Test
    void estimatedMemoryUsageDecreasesWhenDataIsRead() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 100));
        receiveBuffer.add(new DataFrame(100, 200));

        // When
        receiveBuffer.read(ByteBuffer.allocate(150));

        // Then
        assertThat(receiveBuffer.estimatedMemoryUsage()).isEqualTo(150 + 1 * ReceiveBufferImpl.FRAME_OVERHEAD);
    }

    @Test
    void estimatedMemoryUsageIsZeroWhenAllDataIsRead() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 100));
        receiveBuffer.add(new DataFrame(100, 200));

        // When
        receiveBuffer.read(ByteBuffer.allocate(1000));

        // Then
        assertThat(receiveBuffer.estimatedMemoryUsage()).isEqualTo(0);
    }

    @Test
    void estimatedMemoryUsageIncludesOutOfOrderDataAndFrameOverhead() throws Exception {
        // When
        receiveBuffer.add(new DataFrame(200, 100));
        receiveBuffer.add(new DataFrame(500, 300));

        // Then
        assertThat(receiveBuffer.estimatedMemoryUsage()).isEqualTo(400 + 2 * ReceiveBufferImpl.FRAME_OVERHEAD);
    }

    @Test
    void estimatedMemoryUsageAccountsForCombinedOutOfOrderFrames() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(200, 100));

        // When                         overlapping, so combined into 200..349
        receiveBuffer.add(new DataFrame(250, 100));

        // Then
        assertThat(receiveBuffer.estimatedMemoryUsage()).isEqualTo(150 + 1 * ReceiveBufferImpl.FRAME_OVERHEAD);
    }

    @Test
    void estimatedMemoryUsageIncludesBothContiguousAndOutOfOrderFrames() throws Exception {
        // When
        receiveBuffer.add(new DataFrame(0, 100));
        receiveBuffer.add(new DataFrame(200, 100));

        // Then
        assertThat(receiveBuffer.estimatedMemoryUsage()).isEqualTo(200 + 2 * ReceiveBufferImpl.FRAME_OVERHEAD);
    }

    @Test
    void estimatedMemoryUsageIsUpdatedWhenOutOfOrderFramesBecomeContiguous() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(100, 100));
        receiveBuffer.add(new DataFrame(300, 100));

        // When
        receiveBuffer.add(new DataFrame(0, 100));

        // Then
        assertThat(receiveBuffer.estimatedMemoryUsage()).isEqualTo(300 + 3 * ReceiveBufferImpl.FRAME_OVERHEAD);
    }

    @Test
    void estimatedMemoryUsageIsZeroWhenAllDataIsDiscarded() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(0, 100));
        receiveBuffer.add(new DataFrame(200, 100));

        // When
        receiveBuffer.discardAllData();

        // Then
        assertThat(receiveBuffer.estimatedMemoryUsage()).isEqualTo(0);
    }
    // endregion

    // region compaction of contiguous frames
    private static final int SMALL_BUFFER_SIZE = 10_000;

    @Test
    void whenManySmallFramesAreAddedInOrderWithoutReadingMemoryUsageIsLimited() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);

        // When
        for (int i = 0; i < SMALL_BUFFER_SIZE; i++) {
            buffer.add(new DataFrame(i, 1));
        }

        // Then
        assertThat(buffer.estimatedMemoryUsage())
                .isGreaterThan(SMALL_BUFFER_SIZE)
                .isLessThan(SMALL_BUFFER_SIZE * 2);

        checkAllDataCanBeRead(buffer, SMALL_BUFFER_SIZE);
    }

    @Test
    void whenMemoryUsageIsLowFramesAreNotCompacted() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);

        // When
        for (int i = 0; i < 10; i++) {
            buffer.add(new DataFrame(i, 1));
        }

        // Then
        assertThat(buffer.countContiguousFrames()).isEqualTo(10);
    }

    @Test
    void whenFrameDoesNotFitInChunkItIsSpreadOverNextChunk() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
        int offset = fillWithSmallFramesUntilCompacting(buffer);

        // When
        buffer.add(new DataFrame(offset, 2000));
        buffer.add(new DataFrame(offset + 2000, 2000));

        // Then
        checkAllDataCanBeRead(buffer, offset + 4000);
    }

    @Test
    void whenLargeFrameIsAddedAfterPartlyFilledChunkTheChunkIsFilledFirst() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
        int offset = fillWithSmallFramesUntilCompacting(buffer);
        buffer.add(new DataFrame(offset, 10));

        // When
        buffer.add(new DataFrame(offset + 10, 3 * MAX_COMBINED_FRAME_SIZE));

        // Then
        checkAllDataCanBeRead(buffer, offset + 10 + 3 * MAX_COMBINED_FRAME_SIZE);
    }

    @Test
    void whenOutOfOrderFramesBecomeContiguousTheyAreCompactedToo() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
        int offset = fillWithSmallFramesUntilCompacting(buffer);
        for (int i = 1; i < 20; i++) {
            buffer.add(new DataFrame(offset + 2 * i, 1));  // offset + 2, offset + 4, offset + 6, ...
        }

        // When
        for (int i = 0; i < 20; i++) {
            buffer.add(new DataFrame(offset + 2 * i + 1, 1));  // offset + 1, offset + 3, offset + 5, ...
        }
        buffer.add(new DataFrame(offset, 1));  // offset + 0, to make the whole range contiguous

        // Then
        assertThat(buffer.countOutOfOrderFrames()).isEqualTo(0);
        checkAllDataCanBeRead(buffer, offset + 40);
    }

    @Test
    void whenReadBufferIsSmallerThenChunkNextReadReadsFromChunk() throws Exception {
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
        int offset = fillWithSmallFramesUntilCompacting(buffer);
        buffer.add(new DataFrame(offset, 70));
        ByteBuffer readData = ByteBuffer.allocate(offset + 100);

        // When
        buffer.read(ByteBuffer.wrap(readData.array(), 0, offset + 50));
        readData.position((int) buffer.readOffset());
        buffer.read(ByteBuffer.wrap(readData.array(), readData.position(), readData.remaining()));

        // Then
        checkData(readData);
    }

    @Test
    void afterPartialReadFromChunkNextReadAfterAddContinuesFromChunk() throws Exception {
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
        int offset = fillWithSmallFramesUntilCompacting(buffer);
        buffer.add(new DataFrame(offset, 40));
        ByteBuffer readData = ByteBuffer.allocate(offset + 100);

        // When
        buffer.read(readData);
        buffer.add(new DataFrame(offset + 40, 30));
        buffer.read(readData);

        // Then
        checkData(readData);
    }

    @Test
    void whenAddingAndReadingSmallFramesAllDataIsReadCorrectly() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
        Random random = new Random(7);
        int streamSize = 100_000;
        ByteBuffer readData = ByteBuffer.allocate(streamSize);

        // When
        int offset = 0;
        while (offset < streamSize) {
            int length = Integer.min(1 + random.nextInt(100), streamSize - offset);
            buffer.add(new DataFrame(offset, length));
            offset += length;
            if (random.nextInt(10) == 0) {
                buffer.read(ByteBuffer.wrap(readData.array(), readData.position(), random.nextInt(1000)));
                readData.position((int) buffer.readOffset());
            }
        }
        buffer.read(readData);

        // Then
        assertThat(readData.position()).isEqualTo(streamSize);
        checkData(readData);
    }

    @Test
    void whenFinalFrameEndsInChunkEndOfStreamIsDetected() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
        int offset = fillWithSmallFramesUntilCompacting(buffer);

        // When
        buffer.add(new DataFrame(offset, 10, true));

        // Then
        checkAllDataCanBeRead(buffer, offset + 10);
        assertThat(buffer.allDataReceived()).isTrue();
        assertThat(buffer.allRead()).isTrue();
        assertThat(buffer.read(ByteBuffer.allocate(100))).isEqualTo(-1);
    }

    @Test
    void whenFinalFrameEndsInChunkAndAllDataIsReadMemoryIsReleased() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
        int offset = fillWithSmallFramesUntilCompacting(buffer);
        buffer.add(new DataFrame(offset, 10, true));

        // When
        checkAllDataCanBeRead(buffer, offset + 10);

        // Then
        assertThat(buffer.allRead()).isTrue();
        assertThat(buffer.countContiguousFrames()).isEqualTo(0);
        assertThat(buffer.estimatedMemoryUsage()).isEqualTo(0);
    }

    @Test
    void whenEmptyFinalFrameIsReceivedAfterAllDataInChunkIsReadMemoryIsReleased() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
        int offset = fillWithSmallFramesUntilCompacting(buffer);
        buffer.add(new DataFrame(offset, 10));
        checkAllDataCanBeRead(buffer, offset + 10);

        // When
        buffer.add(new DataFrame(offset + 10, 0, true));

        // Then
        assertThat(buffer.read(ByteBuffer.allocate(100))).isEqualTo(-1);
        assertThat(buffer.allRead()).isTrue();
        assertThat(buffer.countContiguousFrames()).isEqualTo(0);
        assertThat(buffer.estimatedMemoryUsage()).isEqualTo(0);
    }

    @Test
    void whenEmptyFinalFrameIsReceivedAfterAllDataInChunkIsReadNoMemoryIsUsedWithoutReadingAgain() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
        int offset = fillWithSmallFramesUntilCompacting(buffer);
        buffer.add(new DataFrame(offset, 10));
        checkAllDataCanBeRead(buffer, offset + 10);

        // When
        buffer.add(new DataFrame(offset + 10, 0, true));

        // Then
        assertThat(buffer.allRead()).isTrue();
        assertThat(buffer.estimatedMemoryUsage()).isEqualTo(0);
    }

    @Test
    void whenDuplicateFinalFrameIsReceivedAfterAllDataInChunkIsReadNoMemoryIsUsedWithoutReadingAgain() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
        int offset = fillWithSmallFramesUntilCompacting(buffer);
        buffer.add(new DataFrame(offset, 10));
        checkAllDataCanBeRead(buffer, offset + 10);

        // When  (retransmission of already read data, now with fin bit)
        buffer.add(new DataFrame(offset, 10, true));

        // Then
        assertThat(buffer.allRead()).isTrue();
        assertThat(buffer.estimatedMemoryUsage()).isEqualTo(0);
    }

    @Test
    void whenDataIsDiscardedBeyondOffsetInChunkOnlyDataBeforeOffsetIsRead() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
        int offset = fillWithSmallFramesUntilCompacting(buffer);
        buffer.add(new DataFrame(offset, 100));

        // When
        buffer.discardDataBeyond(offset + 50);

        // Then
        assertThat(buffer.bytesAvailable()).isEqualTo(offset + 50);
        checkAllDataCanBeRead(buffer, offset + 50);
        assertThat(buffer.allRead()).isTrue();
        assertThat(buffer.read(ByteBuffer.allocate(100))).isEqualTo(-1);
    }

    @Test
    void whenAllDataIsDiscardedMemoryUsageIsZero() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
        int offset = fillWithSmallFramesUntilCompacting(buffer);
        buffer.add(new DataFrame(offset, 10));

        // When
        buffer.discardAllData();

        // Then
        assertThat(buffer.estimatedMemoryUsage()).isEqualTo(0);
    }

    @Test
    void whenSmallFramesAreAddedAndReadConcurrentlyAllDataIsReadCorrectly() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
        int streamSize = 1_000_000;
        AtomicReference<Exception> producerError = new AtomicReference<>();
        Thread producer = new Thread(() -> {
            Random random = new Random(11);
            int offset = 0;
            while (offset < streamSize) {
                int length = Integer.min(1 + random.nextInt(50), streamSize - offset);
                // Mimic flow control: never add data beyond the read offset plus the buffer size.
                while (offset + length > buffer.readOffset() + SMALL_BUFFER_SIZE) {
                    Thread.yield();
                }
                try {
                    buffer.add(new DataFrame(offset, length, offset + length == streamSize));
                }
                catch (Exception e) {
                    producerError.set(e);
                    return;
                }
                offset += length;
            }
        });

        // When
        producer.start();
        ByteBuffer readData = ByteBuffer.allocate(streamSize);
        long deadline = System.currentTimeMillis() + 30_000;
        while (buffer.read(ByteBuffer.wrap(readData.array(), readData.position(), Integer.min(997, readData.remaining()))) >= 0
                && producerError.get() == null && System.currentTimeMillis() < deadline) {
            readData.position((int) buffer.readOffset());
        }
        producer.join();

        // Then
        assertThat(producerError.get()).isNull();
        assertThat(readData.position()).isEqualTo(streamSize);
        checkData(readData);
    }

    /**
     * Adds small in-order frames until the overhead is so high that new frames are compacted.
     * @return  the offset up to which data has been added
     */
    private int fillWithSmallFramesUntilCompacting(ReceiveBufferImpl buffer) throws Exception {
        int offset = 0;
        while (!buffer.overheadIsHigh()) {
            buffer.add(new DataFrame(offset, 1));
            offset++;
        }
        return offset;
    }

    private void checkAllDataCanBeRead(ReceiveBufferImpl buffer, int length) {
        ByteBuffer readData = ByteBuffer.allocate(length + 100);
        while (buffer.read(readData) > 0) {
        }
        assertThat(readData.position()).isEqualTo(length);
        checkData(readData);
    }
    // endregion

    // region memory limit
    @Test
    void whenManySmallFramesWithGapsAreAddedTransportErrorIsThrown() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
        long maxMemoryUsage = ReceiveBufferImpl.MAX_MEMORY_FACTOR * SMALL_BUFFER_SIZE;

        // When
        TransportError error = null;
        for (int i = 0; i < SMALL_BUFFER_SIZE / 2 && error == null; i++) {
            try {
                buffer.add(new DataFrame(2 * i + 1, 1));
            }
            catch (TransportError transportError) {
                error = transportError;
            }
        }

        // Then
        assertThat(error).isNotNull();
        assertThat(error.getErrorCode()).isEqualTo(QuicConstants.TransportErrorCode.INTERNAL_ERROR);
        // Exceeded by at most the frame that caused the error
        assertThat(buffer.estimatedMemoryUsage()).isLessThanOrEqualTo(maxMemoryUsage + 1 + ReceiveBufferImpl.FRAME_OVERHEAD);
    }

    @Test
    void whenFramesWithGapsAreNotSmallNoTransportErrorIsThrown() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);

        // When
        for (int offset = 100; offset < SMALL_BUFFER_SIZE; offset += 200) {
            buffer.add(new DataFrame(offset, 100));
        }

        // Then
        assertThat(buffer.estimatedMemoryUsage()).isLessThanOrEqualTo(ReceiveBufferImpl.MAX_MEMORY_FACTOR * SMALL_BUFFER_SIZE);
    }

    @Test
    void whenManySmallFramesAreAddedInOrderWithoutReadingNoTransportErrorIsThrown() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);

        // When
        for (int i = 0; i < SMALL_BUFFER_SIZE; i++) {
            buffer.add(new DataFrame(i, 1));
        }

        // Then
        checkAllDataCanBeRead(buffer, SMALL_BUFFER_SIZE);
    }

    @Test
    void whenSmallAdjacentFramesAreAddedInRandomOrderAfterFirstIsLostNoTransportErrorIsThrown() throws Exception {
        // Given
        int streamSize = 100_000;
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(streamSize, MAX_COMBINED_FRAME_SIZE);
        Random random = new Random(13);
        List<DataFrame> frames = new ArrayList<>();
        int offset = 0;
        while (offset < streamSize) {
            int length = Integer.min(1 + random.nextInt(100), streamSize - offset);
            frames.add(new DataFrame(offset, length));
            offset += length;
        }
        DataFrame firstFrame = frames.remove(0);
        Collections.shuffle(frames, random);

        // When
        for (DataFrame frame : frames) {
            buffer.add(frame);
        }
        buffer.add(firstFrame);

        // Then
        checkAllDataCanBeRead(buffer, streamSize);
    }

    @Test
    void whenSmallAdjacentFramesAreAddedInAscendingOrderAfterFirstIsLostNoTransportErrorIsThrown() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
        Random random = new Random(17);
        int offset = 100;

        // When
        while (offset < SMALL_BUFFER_SIZE) {
            int length = Integer.min(1 + random.nextInt(100), SMALL_BUFFER_SIZE - offset);
            buffer.add(new DataFrame(offset, length));
            offset += length;
        }
        buffer.add(new DataFrame(0, 100));

        // Then
        checkAllDataCanBeRead(buffer, SMALL_BUFFER_SIZE);
    }

    @Test
    void whenSingleByteFramesAreAddedInAscendingOrderAfterFirstIsLostNoTransportErrorIsThrown() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);

        // When
        for (int offset = 1; offset < SMALL_BUFFER_SIZE; offset++) {
            buffer.add(new DataFrame(offset, 1));
        }
        buffer.add(new DataFrame(0, 1));

        // Then
        checkAllDataCanBeRead(buffer, SMALL_BUFFER_SIZE);
    }

    @Test
    void whenSingleByteFramesAreAddedInDescendingOrderNoTransportErrorIsThrown() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);

        // When
        for (int offset = SMALL_BUFFER_SIZE - 1; offset >= 0; offset--) {
            buffer.add(new DataFrame(offset, 1));
        }

        // Then
        checkAllDataCanBeRead(buffer, SMALL_BUFFER_SIZE);
    }

    @Test
    void whenAllDataIsDiscardedNoTransportErrorIsThrown() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
        buffer.discardAllData();

        // When
        for (int i = 0; i < SMALL_BUFFER_SIZE / 2; i++) {
            buffer.add(new DataFrame(2 * i + 1, 1));
        }

        // Then
        assertThat(buffer.estimatedMemoryUsage()).isEqualTo(0);
    }

    @Test
    void framesBeyondDiscardOffsetDoNotCountForMemoryLimit() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
        long maxMemoryUsage = ReceiveBufferImpl.MAX_MEMORY_FACTOR * SMALL_BUFFER_SIZE;
        // Fill the buffer with small frames with gaps, up to just below the memory limit
        long offset = SMALL_BUFFER_SIZE / 2 + 1;
        while (buffer.estimatedMemoryUsage() + 1 + ReceiveBufferImpl.FRAME_OVERHEAD <= maxMemoryUsage) {
            buffer.add(new DataFrame(offset, 1));
            offset += 2;
        }
        buffer.discardDataBeyond(SMALL_BUFFER_SIZE / 10);

        // When
        for (int i = 0; i < 100; i++) {
            buffer.add(new DataFrame(2 * i + 1, 1));
        }

        // Then
        assertThat(buffer.estimatedMemoryUsage()).isLessThanOrEqualTo(100 * (1 + ReceiveBufferImpl.FRAME_OVERHEAD));
    }
    // endregion

    // region connection memory budget
    @Test
    void connectionMemoryBudgetContainsOverheadOfAllBuffers() throws Exception {
        // Given
        ConnectionMemoryBudget budget = createConnectionMemoryBudget(SMALL_BUFFER_SIZE);
        ReceiveBufferImpl buffer1 = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE, budget);
        ReceiveBufferImpl buffer2 = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE, budget);

        // When
        buffer1.add(new DataFrame(0, 100));
        buffer1.add(new DataFrame(200, 100));
        buffer2.add(new DataFrame(100, 100));

        // Then
        assertThat(budget.getOverhead()).isEqualTo(3 * ReceiveBufferImpl.FRAME_OVERHEAD);
    }

    @Test
    void whenDataIsReadOverheadIsRemovedFromConnectionMemoryBudget() throws Exception {
        // Given
        ConnectionMemoryBudget budget = createConnectionMemoryBudget(SMALL_BUFFER_SIZE);
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE, budget);
        buffer.add(new DataFrame(0, 100));
        buffer.add(new DataFrame(100, 100));

        // When
        buffer.read(ByteBuffer.allocate(150));

        // Then
        assertThat(budget.getOverhead()).isEqualTo(ReceiveBufferImpl.FRAME_OVERHEAD);
    }

    @Test
    void whenAllDataIsReadConnectionMemoryBudgetIsZero() throws Exception {
        // Given
        ConnectionMemoryBudget budget = createConnectionMemoryBudget(SMALL_BUFFER_SIZE);
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE, budget);
        int offset = 0;
        while (!buffer.overheadIsHigh()) {
            buffer.add(new DataFrame(offset, 1));
            offset++;
        }
        // Final frame that is compacted into a chunk that is not completely filled
        buffer.add(new DataFrame(offset, 10, true));

        // When
        checkAllDataCanBeRead(buffer, offset + 10);

        // Then
        assertThat(budget.getOverhead()).isEqualTo(0);
    }

    @Test
    void whenAllDataIsDiscardedConnectionMemoryBudgetIsZero() throws Exception {
        // Given
        ConnectionMemoryBudget budget = createConnectionMemoryBudget(SMALL_BUFFER_SIZE);
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE, budget);
        buffer.add(new DataFrame(0, 100));
        buffer.add(new DataFrame(200, 100));

        // When
        buffer.discardAllData();

        // Then
        assertThat(budget.getOverhead()).isEqualTo(0);
    }

    @Test
    void whenDataBeyondReadOffsetIsDiscardedConnectionMemoryBudgetIsZero() throws Exception {
        // Given
        ConnectionMemoryBudget budget = createConnectionMemoryBudget(SMALL_BUFFER_SIZE);
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE, budget);
        buffer.add(new DataFrame(0, 100));
        buffer.add(new DataFrame(200, 100));
        buffer.read(ByteBuffer.allocate(100));

        // When
        buffer.discardDataBeyond(100);

        // Then
        assertThat(budget.getOverhead()).isEqualTo(0);
    }

    @Test
    void whenDataBeyondReadOffsetIsDiscardedAllDataIsPurged() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
        buffer.add(new DataFrame(0, 100));
        buffer.add(new DataFrame(100, 100));
        buffer.add(new DataFrame(300, 100));
        buffer.read(ByteBuffer.allocate(150));

        // When
        buffer.discardDataBeyond(120);

        // Then
        assertThat(buffer.estimatedOverhead()).isEqualTo(0);
        assertThat(buffer.bufferedOutOfOrderData()).isEqualTo(0);
        assertThat(buffer.read(ByteBuffer.allocate(100))).isEqualTo(-1);
    }

    @Test
    void whenDataBeyondUnreadOffsetIsDiscardedDataBeforeOffsetCanStillBeRead() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
        buffer.add(new DataFrame(0, 100));
        buffer.add(new DataFrame(100, 100));
        buffer.read(ByteBuffer.allocate(50));

        // When
        buffer.discardDataBeyond(120);

        // Then
        assertThat(buffer.estimatedOverhead()).isEqualTo(2 * ReceiveBufferImpl.FRAME_OVERHEAD);
        assertThat(buffer.read(ByteBuffer.allocate(100))).isEqualTo(70);
        assertThat(buffer.read(ByteBuffer.allocate(100))).isEqualTo(-1);
    }

    @Test
    void whenEmptyFinalFrameIsReceivedAfterAllDataIsReadConnectionMemoryBudgetIsZero() throws Exception {
        // Given
        ConnectionMemoryBudget budget = createConnectionMemoryBudget(SMALL_BUFFER_SIZE);
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE, budget);
        int offset = 0;
        while (!buffer.overheadIsHigh()) {
            buffer.add(new DataFrame(offset, 1));
            offset++;
        }
        // Frame that is compacted into a chunk that is not completely filled (so the chunk remains after reading)
        buffer.add(new DataFrame(offset, 10));
        checkAllDataCanBeRead(buffer, offset + 10);
        assertThat(budget.getOverhead()).isGreaterThan(0);

        // When
        buffer.add(new DataFrame(offset + 10, 0, true));

        // Then
        assertThat(buffer.read(ByteBuffer.allocate(10))).isEqualTo(-1);
        assertThat(budget.getOverhead()).isEqualTo(0);
    }

    @Test
    void whenSmallFramesWithGapsAreSpreadOverManyBuffersTransportErrorIsThrown() throws Exception {
        // Given
        int connectionBufferSize = SMALL_BUFFER_SIZE;
        ConnectionMemoryBudget budget = createConnectionMemoryBudget(connectionBufferSize);
        long maxOverhead = (ReceiveBufferImpl.MAX_MEMORY_FACTOR - 1) * connectionBufferSize;
        List<ReceiveBufferImpl> buffers = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            buffers.add(new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE, budget));
        }

        // When
        TransportError error = null;
        for (int i = 0; i < SMALL_BUFFER_SIZE / 2 && error == null; i++) {
            for (ReceiveBufferImpl buffer : buffers) {
                try {
                    buffer.add(new DataFrame(2 * i + 1, 1));
                }
                catch (TransportError transportError) {
                    error = transportError;
                    break;
                }
            }
        }

        // Then
        assertThat(error).isNotNull();
        assertThat(error.getErrorCode()).isEqualTo(QuicConstants.TransportErrorCode.INTERNAL_ERROR);
        // Exceeded by at most the frame that caused the error
        assertThat(budget.getOverhead()).isLessThanOrEqualTo(maxOverhead + ReceiveBufferImpl.FRAME_OVERHEAD);
        // Each buffer is well within its own limit
        assertThat(buffers.get(0).estimatedMemoryUsage()).isLessThan(ReceiveBufferImpl.MAX_MEMORY_FACTOR * SMALL_BUFFER_SIZE / 10);
    }

    private ConnectionMemoryBudget createConnectionMemoryBudget(long connectionBufferSize) {
        ConnectionMemoryBudget budget = new ConnectionMemoryBudget();
        budget.setConnectionBufferSize(connectionBufferSize);
        return budget;
    }
    // endregion

    // region memory management
    @Test
    void duplicatedFramesAreCombinedToReduceMemoryUsage() throws Exception {
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
    void duplicatedFramesAreCombinedToReduceMemoryUsage2() throws Exception {
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
    void duplicatedFramesAreCombinedToReduceMemoryUsage3() throws Exception {
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
    void whenDuplicatedFramesWithDifferentFinalFlagAreCombinedFinalIsStillSet() throws Exception {
        // Given
        receiveBuffer.add(new DataFrame(20, 100));

        // When
        receiveBuffer.add(new DataFrame(20, 100, true));
        receiveBuffer.add(new DataFrame(0, 120));

        // Then
        assertThat(receiveBuffer.allDataReceived()).isTrue();
    }

    @Test
    void containingFramesAreCombinedToReduceMemoryUsage() throws Exception {
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
    void containingFramesAreCombinedToReduceMemoryUsage2() throws Exception {
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
    void overlappingFramesAreCombinedToReduceMemoryUsage1() throws Exception {
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
    void overlappingFramesAreCombinedToReduceMemoryUsage2() throws Exception {
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
    void overlappingFramesAreCombinedToReduceMemoryUsage3() throws Exception {
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
    void multipleOverlappingFramesAreCombinedToReduceMemoryUsage1() throws Exception {
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
    void multipleOverlappingFramesAreCombinedToReduceMemoryUsage2() throws Exception {
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
    void multipleOverlappingFramesAreCombinedToReduceMemoryUsage3() throws Exception {
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
    void multipleOverlappingFramesWithGapsAreCombinedToReduceMemoryUsage1() throws Exception {
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
    void multipleOverlappingFramesAreCombinedToReduceMemoryUsage() throws Exception {
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
    void frameShouldNotBeCombinedWithBeforeWhenLargerThanMax() throws Exception {
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
    void frameShouldNotBeCombinedWithAfterWhenLargerThanMax() throws Exception {
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
    void whenShrunkFrameOverlapsWithFormerNextThatHoweverBecomesBefore() throws Exception {
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
    void addZeroSizeFrame() throws Exception {
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
    void whenFramesAreAddedToContiguousStreamOverlapIsRemoved() throws Exception {
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
    void whenFrameLargerThanMaxCombinedFrameSizeContainsExistingFrameNoDataIsLost() throws Exception {
        // Given                        1000..1099
        receiveBuffer.add(new DataFrame(1000, 100));

        // When                         10..3009 (larger than max combined frame size)
        receiveBuffer.add(new DataFrame(10, 3000));

        // Then
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        checkDataCanBeReadAfterAdding(3010, new DataFrame(0, 10));
    }

    @Test
    void whenFrameIsContainedInExistingFrameLargerThanMaxCombinedFrameSizeOverlapIsRemoved() throws Exception {
        // Given                        1000..3999 (larger than max combined frame size)
        receiveBuffer.add(new DataFrame(1000, 3000));

        // When                         1500..1999
        receiveBuffer.add(new DataFrame(1500, 500));

        // Then
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        checkDataCanBeReadAfterAdding(4000, new DataFrame(0, 1000));
    }

    @Test
    void whenFrameIsContainedInFrameCombinedUpToMaxCombinedFrameSizeOverlapIsRemoved() throws Exception {
        // Given                        1000..2199, 2100..3299, 3200..3499 (combined into 1000..3499, exactly max size)
        receiveBuffer.add(new DataFrame(1000, 1200));
        receiveBuffer.add(new DataFrame(2100, 1200));
        receiveBuffer.add(new DataFrame(3200, 300));

        // When                         1500..1999
        receiveBuffer.add(new DataFrame(1500, 500));

        // Then
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        checkDataCanBeReadAfterAdding(3500, new DataFrame(0, 1000));
    }
    // endregion

    // region contains and combine helper methods
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

    @Test
    void combineAdjacentFrames() {
        // Given
        DataFrame frame1 = new DataFrame(100, 30);  // 100..129
        DataFrame frame2 = new DataFrame(130, 60);  // 130..189

        // When
        StreamElement combined = ReceiveBufferImpl.combine(frame1, frame2);

        assertThat(combined.getOffset()).isEqualTo(100);
        assertThat(combined.getLength()).isEqualTo(90);
        assertThat(ReceiveBufferImpl.combinedLength(frame1, frame2)).isEqualTo(combined.getLength());
        checkData(ByteBuffer.wrap(combined.getStreamData()));
    }

    @Test
    void combineListOfAdjacentFrames() {
        // Given
        DataFrame frame1 = new DataFrame(100, 30);  // 100..129
        DataFrame frame2 = new DataFrame(130, 60);  // 130..189
        DataFrame frame3 = new DataFrame(190, 10);  // 190..199

        // When
        StreamElement combined = ReceiveBufferImpl.combine(List.of(frame1, frame2, frame3), 100, 200);

        // Then
        assertThat(combined.getOffset()).isEqualTo(100);
        assertThat(combined.getLength()).isEqualTo(100);
        checkFrameData(combined);
    }

    @Test
    void combineListOfOverlappingAndAdjacentFrames() {
        // Given
        DataFrame frame1 = new DataFrame(100, 50);  // 100..149
        DataFrame frame2 = new DataFrame(140, 30);  // 140..169
        DataFrame frame3 = new DataFrame(170, 20);  // 170..189
        DataFrame frame4 = new DataFrame(190, 10);  // 185..199

        // When
        StreamElement combined = ReceiveBufferImpl.combine(List.of(frame1, frame2, frame3, frame4), 100, 200);

        // Then
        assertThat(combined.getOffset()).isEqualTo(100);
        assertThat(combined.getLength()).isEqualTo(100);
        checkFrameData(combined);
    }

    @Test
    void combineListOfFramesWhereFirstContainsAllOthers() {
        // Given
        DataFrame frame1 = new DataFrame(100, 100);  // 100..199
        DataFrame frame2 = new DataFrame(120, 10);   // 120..129
        DataFrame frame3 = new DataFrame(150, 50);   // 150..199

        // When
        StreamElement combined = ReceiveBufferImpl.combine(List.of(frame1, frame2, frame3), 100, 200);

        // Then
        assertThat(combined).isSameAs(frame1);
    }

    @Test
    void combineListOfFramesWhereLaterFrameContainsAllOthers() {
        // Given
        DataFrame frame1 = new DataFrame(100, 10);  // 100..109
        DataFrame frame2 = new DataFrame(100, 50);  // 100..149

        // When
        StreamElement combined = ReceiveBufferImpl.combine(List.of(frame1, frame2), 100, 150);

        // Then
        assertThat(combined).isSameAs(frame2);
    }

    @Test
    void combineListOfFramesUpToOffsetBeforeEndOfLastFrame() {
        // Given
        DataFrame frame1 = new DataFrame(100, 50);  // 100..149
        DataFrame frame2 = new DataFrame(150, 50);  // 150..199

        // When
        StreamElement combined = ReceiveBufferImpl.combine(List.of(frame1, frame2), 100, 170);

        // Then
        assertThat(combined.getOffset()).isEqualTo(100);
        assertThat(combined.getLength()).isEqualTo(70);
        checkFrameData(combined);
    }

    @Test
    void combineListOfSingleFrameUpToOffsetBeforeEndOfFrame() {
        // Given
        DataFrame frame = new DataFrame(100, 100);  // 100..199

        // When
        StreamElement combined = ReceiveBufferImpl.combine(List.of(frame), 100, 150);

        // Then
        assertThat(combined.getOffset()).isEqualTo(100);
        assertThat(combined.getLength()).isEqualTo(50);
        checkFrameData(combined);
    }

    @Test
    void combineListOfFramesKeepsFinalFlag() {
        // Given
        DataFrame frame1 = new DataFrame(100, 10);
        DataFrame frame2 = new DataFrame(110, 10, true);

        // When
        StreamElement combined = ReceiveBufferImpl.combine(List.of(frame1, frame2), 100, 120);

        // Then
        assertThat(combined.isFinal()).isTrue();
    }

    @Test
    void combineListOfFramesIsNotFinalWhenEndOfFinalFrameIsDropped() {
        // Given
        DataFrame frame1 = new DataFrame(100, 10);               // 100..109
        DataFrame frame2 = new DataFrame(110, 10, true);  // 110..119

        // When
        StreamElement combined = ReceiveBufferImpl.combine(List.of(frame1, frame2), 100, 115);

        // Then
        assertThat(combined.getLength()).isEqualTo(15);
        assertThat(combined.isFinal()).isFalse();
    }

    @Test
    void combineListOfSingleFinalFrameIsNotFinalWhenEndIsDropped() {
        // Given
        DataFrame frame = new DataFrame(100, 100, true);  // 100..199

        // When
        StreamElement combined = ReceiveBufferImpl.combine(List.of(frame), 100, 150);

        // Then
        assertThat(combined.getLength()).isEqualTo(50);
        assertThat(combined.isFinal()).isFalse();
    }

    @Test
    void whenFragmentedAdjacentFramesArrivingInAscendingOrderAreCombined() throws Exception {
        // When
        for (int offset = 1; offset <= 20000; offset++) {
            receiveBuffer.add(new DataFrame(offset, 1));
        }

        // Then
        checkAdjacentFramesAreCombined(20000);
    }

    @Test
    void whenFragmentedAdjacentFramesArrivingInDescendingOrderAreCombined() throws Exception {
        // When
        for (int offset = 20000; offset >= 1; offset--) {
            receiveBuffer.add(new DataFrame(offset, 1));
        }

        // Then
        checkAdjacentFramesAreCombined(20000);
    }

    private void checkAdjacentFramesAreCombined(int framesAdded) throws Exception {
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(framesAdded);
        assertThat(receiveBuffer.checkOverlap()).isEqualTo(0);
        // Combining only starts when the overhead is high, so not all frames will be combined.
        assertThat(receiveBuffer.countOutOfOrderFrames()).isLessThan(framesAdded * 3 / 4);
        assertThat(receiveBuffer.maxOutOfOrderFrameSize()).isLessThanOrEqualTo(MAX_COMBINED_FRAME_SIZE);

        receiveBuffer.add(new DataFrame(0, 1));
        ByteBuffer readBytes = ByteBuffer.allocate(framesAdded + 1);
        assertThat(receiveBuffer.read(readBytes)).isEqualTo(framesAdded + 1);
        checkData(readBytes);
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(0);
    }

    @Test
    void whenDuplicateOfFrameIsCombinedWithAdjacentFrameOriginalFrameShouldBeRemoved() throws Exception {
        // Given
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(SMALL_BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
        // Two adjacent frames that are not combined, because the overhead is not (yet) high.
        buffer.add(new DataFrame(100, 10));
        buffer.add(new DataFrame(110, 10));
        assertThat(buffer.countOutOfOrderFrames()).isEqualTo(2);
        // Small frames with gaps in between (that cannot be combined) to make the overhead high.
        int offset = 1000;
        while (!buffer.overheadIsHigh()) {
            buffer.add(new DataFrame(offset, 1));
            offset += 2;
        }
        long bufferedBefore = buffer.bufferedOutOfOrderData();

        // When
        buffer.add(new DataFrame(100, 10));

        // Then
        assertThat(buffer.checkOverlap()).isEqualTo(0);
        assertThat(buffer.bufferedOutOfOrderData()).isEqualTo(bufferedBefore);
    }
    // endregion

    // region stress test
    @Test
    void testRandomStreamElementAdditions() throws Exception {
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
        }
        catch (AssertionError e) {
            System.out.println("Assert failed while adding " + frame + " to " + bufferContentBefore + " resulting in " + receiveBuffer.toDebugString(5000));
            throw e;
        }
    }

    @Test
    void fuzzTestAddingRandomFramesAndReadingAllData() throws Exception {
        for (int round = 0; round < 100; round++) {
            addRandomFramesAndReadAllData(new Random().nextLong());
        }
    }

    private void addRandomFramesAndReadAllData(long seed) throws Exception {
        Random random = new Random(seed);
        int streamSize = 10_000;
        byte[] original = new byte[streamSize];
        random.nextBytes(original);
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(BUFFER_SIZE, MAX_COMBINED_FRAME_SIZE);
        // One byte extra, to detect reading more data than the stream contains.
        ByteBuffer readData = ByteBuffer.allocate(streamSize + 1);

        int framesAdded = 0;
        int totalBytesRead = 0;
        while (!buffer.allRead()) {
            assertThat(framesAdded).as("frames added (seed %d)", seed).isLessThan(1_000_000);
            int length = random.nextInt(1201);
            int offset = random.nextInt(streamSize - length + 1);
            StreamFrame streamFrame = new StreamFrame(0, offset, original, offset, length, offset + length == streamSize);
            buffer.add(streamFrame);
            framesAdded++;
            int bytesRead = buffer.read(readData);
            if (bytesRead >= 0) {
                totalBytesRead += bytesRead;
            }
        }

        checkAllDataRead(original, readData, totalBytesRead, seed);
    }

    @Test
    void fuzzTestAddingSmallAdjacentFramesInRandomOrderAndReadingAllData() throws Exception {
        for (int round = 0; round < 20; round++) {
            addSmallAdjacentFramesInRandomOrderAndReadAllData(new Random().nextLong());
        }
    }

    private void addSmallAdjacentFramesInRandomOrderAndReadAllData(long seed) throws Exception {
        Random random = new Random(seed);
        // Buffer size equals stream size, so the overhead of small out-of-order frames becomes high enough to combine them.
        int streamSize = 100_000;
        int maxFrameLength = 100;
        byte[] original = new byte[streamSize];
        random.nextBytes(original);
        ReceiveBufferImpl buffer = new ReceiveBufferImpl(streamSize, MAX_COMBINED_FRAME_SIZE);
        // One byte extra, to detect reading more data than the stream contains.
        ByteBuffer readData = ByteBuffer.allocate(streamSize + 1);

        // Split the stream in small adjacent frames ...
        List<StreamFrame> frames = new ArrayList<>();
        int offset = 0;
        while (offset < streamSize) {
            int length = Integer.min(1 + random.nextInt(maxFrameLength), streamSize - offset);
            frames.add(new StreamFrame(0, offset, original, offset, length, offset + length == streamSize));
            offset += length;
        }
        // ... and add them in random order, sometimes repeating a frame that was already added.
        Collections.shuffle(frames, random);

        int totalBytesRead = 0;
        boolean framesCombined = false;
        for (int i = 0; i < frames.size(); i++) {
            buffer.add(frames.get(i));
            if (random.nextInt(10) == 0) {
                buffer.add(frames.get(random.nextInt(i + 1)));
            }
            // As frames do not partially overlap, a frame larger than the maximum frame length can only be the result
            // of combining adjacent frames.
            framesCombined |= buffer.maxOutOfOrderFrameSize() > maxFrameLength;
            int bytesRead = buffer.read(readData);
            if (bytesRead >= 0) {
                totalBytesRead += bytesRead;
            }
        }

        assertThat(buffer.allRead()).as("all read (seed %d)", seed).isTrue();
        assertThat(framesCombined).as("adjacent frames combined (seed %d)", seed).isTrue();
        checkAllDataRead(original, readData, totalBytesRead, seed);
    }

    private void checkAllDataRead(byte[] original, ByteBuffer readData, int totalBytesRead, long seed) {
        int streamSize = original.length;
        assertThat(totalBytesRead).as("bytes read (seed %d)", seed).isEqualTo(streamSize);
        assertThat(readData.position()).as("bytes read (seed %d)", seed).isEqualTo(streamSize);
        assertThat(Arrays.copyOf(readData.array(), streamSize)).as("data read (seed %d)", seed).isEqualTo(original);
    }
    // endregion

    // region helper methods
    private void checkFrameData(StreamElement frame) {
        byte[] data = frame.getStreamData();
        assertThat(data).hasSize(frame.getLength());
        for (int i = 0; i < data.length; i++) {
            assertThat(data[i]).isEqualTo((byte) (frame.getOffset() + i));
        }
    }

    private void checkData(ByteBuffer buffer) {
        for (int i = 0; i < buffer.position(); i++) {
            assertThat(buffer.get(i)).isEqualTo((byte) i);
        }
    }

    private void checkDataCanBeReadAfterAdding(int length, DataFrame... dataFrames) throws Exception {
        for (DataFrame frame : dataFrames) {
            receiveBuffer.add(frame);
        }
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
    // endregion
}
