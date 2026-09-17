package tech.kwik.core.stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.impl.QuicConnectionImpl;
import tech.kwik.core.impl.Role;
import tech.kwik.core.log.Logger;
import tech.kwik.core.test.FieldSetter;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class FlowControlAutoTuningTest {

    private StreamInputStreamImpl streamInputStream;

    @BeforeEach
    void setUp() {
        StreamManager sm = mock(StreamManager.class);
        QuicStreamImpl qs = new QuicStreamImpl(0, Role.Client, mock(QuicConnectionImpl.class), sm, mock(FlowControl.class));
        streamInputStream = new StreamInputStreamImpl(qs, 50_000L, true, 512 * 1024L, mock(Logger.class));
    }

    @Test
    void windowGrowsUnderHighThroughput() throws Exception {
        FieldSetter.setField(streamInputStream, "autoTuneLastCheckTime", Instant.now().minusMillis(500));
        streamInputStream.addDataFrom(new StreamFrame(0, 0, new byte[30_000], false));
        streamInputStream.read(new byte[30_000], 0, 30_000);
        assertThat(getLimit()).isGreaterThan(50_000L);
    }

    @Test
    void windowDoesNotGrowWhenDisabled() throws Exception {
        StreamManager sm = mock(StreamManager.class);
        QuicStreamImpl qs = new QuicStreamImpl(0, Role.Client, mock(QuicConnectionImpl.class), sm, mock(FlowControl.class));
        StreamInputStreamImpl disabledStream = new StreamInputStreamImpl(qs, 50_000L, false, 512 * 1024L, mock(Logger.class));

        FieldSetter.setField(disabledStream, "autoTuneLastCheckTime", Instant.now().minusMillis(500));
        disabledStream.addDataFrom(new StreamFrame(0, 0, new byte[30_000], false));
        disabledStream.read(new byte[30_000], 0, 30_000);

        var f = StreamInputStreamImpl.class.getDeclaredField("receiverFlowControlLimit");
        f.setAccessible(true);
        long limit = (long) f.get(disabledStream);
        assertThat(limit).isEqualTo(50_000L + 30_000L);
    }

    @Test
    void windowRespectsConfiguredMaxLimit() throws Exception {
        StreamManager sm = mock(StreamManager.class);
        QuicStreamImpl qs = new QuicStreamImpl(0, Role.Client, mock(QuicConnectionImpl.class), sm, mock(FlowControl.class));
        long customMax = 100_000L;
        StreamInputStreamImpl customStream = new StreamInputStreamImpl(qs, 50_000L, true, customMax, mock(Logger.class));

        FieldSetter.setField(customStream, "autoTuneLastCheckTime", Instant.now().minusMillis(500));
        customStream.addDataFrom(new StreamFrame(0, 0, new byte[40_000], false));
        customStream.read(new byte[40_000], 0, 40_000);

        var f = StreamInputStreamImpl.class.getDeclaredField("receiverFlowControlLimit");
        f.setAccessible(true);
        long limit = (long) f.get(customStream);
        assertThat(limit).isLessThanOrEqualTo(customMax + 40_000L);
    }

    @Test
    void windowStableUnderLowThroughput() throws Exception {
        streamInputStream.addDataFrom(new StreamFrame(0, 0, new byte[100], false));
        streamInputStream.read(new byte[100], 0, 100);
        assertThat(getLimit()).isEqualTo(50_000L + 100);
    }

    @Test
    void windowRespectsMinLimit() throws Exception {
        StreamManager sm = mock(StreamManager.class);
        QuicStreamImpl qs = new QuicStreamImpl(0, Role.Client, mock(QuicConnectionImpl.class), sm, mock(FlowControl.class));
        long customMin = 64 * 1024L;
        StreamInputStreamImpl customStream = new StreamInputStreamImpl(qs, 10_000L, true, customMin, 512 * 1024L, mock(Logger.class));
        var f = StreamInputStreamImpl.class.getDeclaredField("receiverFlowControlLimit");
        f.setAccessible(true);
        long limit = (long) f.get(customStream);
        assertThat(limit).isGreaterThanOrEqualTo(customMin);
    }

    @Test
    void exposesThroughputAndWindow() throws Exception {
        FieldSetter.setField(streamInputStream, "autoTuneLastCheckTime", Instant.now().minusMillis(500));
        streamInputStream.addDataFrom(new StreamFrame(0, 0, new byte[30_000], false));
        streamInputStream.read(new byte[30_000], 0, 30_000);
        assertThat(streamInputStream.getCurrentThroughput()).isGreaterThan(0L);
        assertThat(streamInputStream.getCurrentReceiveWindow()).isGreaterThan(0L);
    }

    @Test
    void windowShrinksWhenThroughputDrops() throws Exception {
        FieldSetter.setField(streamInputStream, "autoTuneLastCheckTime", Instant.now().minusMillis(500));
        streamInputStream.addDataFrom(new StreamFrame(0, 0, new byte[30_000], false));
        streamInputStream.read(new byte[30_000], 0, 30_000);
        long peakLimit = getLimit();
        assertThat(peakLimit).isGreaterThan(50_000L);

        FieldSetter.setField(streamInputStream, "autoTuneLastCheckTime", Instant.now().minusMillis(500));
        streamInputStream.addDataFrom(new StreamFrame(0, 30_000, new byte[100], false));
        streamInputStream.read(new byte[100], 0, 100);

        assertThat(getLimit()).isEqualTo(peakLimit);
    }

    private long getLimit() throws Exception {
        var f = StreamInputStreamImpl.class.getDeclaredField("receiverFlowControlLimit");
        f.setAccessible(true);
        return (long) f.get(streamInputStream);
    }
}
