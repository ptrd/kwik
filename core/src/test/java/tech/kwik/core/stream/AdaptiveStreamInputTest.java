package tech.kwik.core.stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import tech.kwik.core.Statistics;
import tech.kwik.core.frame.MaxStreamDataFrame;
import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.impl.QuicConnectionImpl;
import tech.kwik.core.impl.Role;
import tech.kwik.core.log.NullLogger;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@Timeout(10)
class AdaptiveStreamInputTest {
    private final AtomicLong clock = new AtomicLong();
    private final QuicConnectionImpl connection = mock(QuicConnectionImpl.class);
    private final StreamManager manager = mock(StreamManager.class);
    private QuicStreamImpl stream;
    private final List<Long> limits = new ArrayList<>();

    @BeforeEach
    void prepare() {
        when(manager.getMaxBidirectionalStreamBufferSize()).thenReturn(8_192L);
        when(manager.getMaxConnectionBufferSize()).thenReturn(65_536L);
        Statistics stats = mock(Statistics.class);
        when(stats.smoothedRtt()).thenReturn(100);
        when(connection.getStats()).thenReturn(stats);
        stream = new QuicStreamImpl(0, Role.Client, connection, manager, mock(FlowControl.class));
        doAnswer(call -> {
            Object frame = call.getArgument(0);
            if (frame instanceof MaxStreamDataFrame) limits.add(((MaxStreamDataFrame) frame).getMaxData());
            return null;
        }).when(connection).send(any(MaxStreamDataFrame.class), any(Consumer.class), eq(true));
    }

    @Test
    void shrinkingKeepsPreviouslyGrantedBytesValidAndEventuallyMakesProgress() throws Exception {
        StreamInputStreamImpl input = new StreamInputStreamImpl(stream, 8_192, new NullLogger(), clock::get);
        input.enableReceiveWindowAutoTuning(1_024, 8_192);
        input.addDataFrom(new StreamFrame(0, 0, new byte[8_192], false));
        for (int i = 0; i < 15; i++) {
            clock.addAndGet(200_000_000);
            assertThat(input.read(new byte[512])).isEqualTo(512);
        }
        assertThat(input.getReceiveWindowSize()).isLessThan(8_192);
        input.addDataFrom(new StreamFrame(0, 8_191, new byte[1], false));
        assertThat(limits).isNotEmpty().isSorted();
        long next = limits.get(limits.size() - 1);
        input.addDataFrom(new StreamFrame(0, 8_192, new byte[(int) (next - 8_192)], false));
        assertThat(input.read(new byte[512])).isEqualTo(512);
        verify(manager, atLeastOnce()).updateConnectionFlowControl(512L);
    }

    @Test
    void sendsCreditWithoutHoldingTheReceiveLock() throws Exception {
        StreamInputStreamImpl input = new StreamInputStreamImpl(stream, 8_192, new NullLogger(), clock::get);
        input.enableReceiveWindowAutoTuning(1_024, 8_192);
        input.addDataFrom(new StreamFrame(0, 0, new byte[2_048], false));
        doAnswer(call -> {
            FutureTask<Long> producer = new FutureTask<>(() -> input.addDataFrom(new StreamFrame(0, 2_048, new byte[1], false)));
            Thread thread = new Thread(producer);
            thread.setDaemon(true);
            thread.start();
            assertThat(producer.get(2, TimeUnit.SECONDS)).isEqualTo(1);
            return null;
        }).when(connection).send(any(MaxStreamDataFrame.class), any(Consumer.class), eq(true));
        assertThat(input.read(new byte[2_048])).isEqualTo(2_048);
    }

    @Test
    void rejectsWindowsLargerThanTheConnectionBudget() {
        assertThatThrownBy(() -> stream.enableReceiveWindowAutoTuning(1_024, 131_072)).isInstanceOf(IllegalArgumentException.class);
        assertThat(stream.getReceiveWindowSize()).isEqualTo(8_192);
    }

    @Test
    void cannotReconfigureAClosedOrAlreadyConfiguredInput() throws Exception {
        StreamInputStreamImpl input = new StreamInputStreamImpl(stream, 8_192, new NullLogger(), clock::get);
        input.enableReceiveWindowAutoTuning(1_024, 8_192);
        assertThatThrownBy(() -> input.enableReceiveWindowAutoTuning(1_024, 8_192)).isInstanceOf(IllegalStateException.class);
        input.close();
        assertThatThrownBy(() -> input.enableReceiveWindowAutoTuning(1_024, 8_192)).isInstanceOf(IllegalStateException.class);
    }

}
