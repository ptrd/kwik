package net.luminis.quic.frame;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;


class MaxStreamsFrameTest {

    @Test
    void serializeAndParse() throws Exception {
        MaxStreamsFrame frame = new MaxStreamsFrame(58, true);
        MaxStreamsFrame recreatedFrame = new MaxStreamsFrame().parse(ByteBuffer.wrap(frame.getBytes()), null);
        assertThat(recreatedFrame.getMaxStreams()).isEqualTo(58);
        assertThat(recreatedFrame.isAppliesToBidirectional()).isTrue();
    }

}