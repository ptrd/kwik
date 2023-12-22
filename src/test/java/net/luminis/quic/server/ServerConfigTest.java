package net.luminis.quic.server;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ServerConfigTest {

    @Test
    void whenMaxConcurrentUnidirectionalStreamsNotSetInProtocolSettingsServerConfigValueShouldBeUsed() {
        // Given
        ServerConfig config = ServerConfig.builder()
                .maxOpenUnidirectionalStreams(10)
                .build();

        // When
        ServerConfig mergedConfig = config.merge(new ApplicationProtocolSettings() {});

        // Then
        assertThat(mergedConfig.maxOpenUnidirectionalStreams()).isEqualTo(10);
    }

    @Test
    void whenMaxConcurrentUnidirectionalStreamsIsSetInProtocolSettingsItShouldBeUsed() {
        // Given
        ServerConfig config = ServerConfig.builder()
                .maxOpenUnidirectionalStreams(10)
                .build();

        // When
        ServerConfig mergedConfig = config.merge(new ApplicationProtocolSettings() {
            @Override
            public int maxConcurrentUnidirectionalStreams() {
                return 3;
            }
        });

        // Then
        assertThat(mergedConfig.maxOpenUnidirectionalStreams()).isEqualTo(3);
    }

    @Test
    void protocolMinBufferSizeIsRespected() {
        // Given
        ServerConfig config = ServerConfig.builder()
                .maxBidirectionalStreamBufferSize(100)
                .build();

        // When
        ServerConfig mergedConfig = config.merge(new ApplicationProtocolSettings() {
            @Override
            public int minBidirectionalStreamReceiverBufferSize() {
                return 1024;
            }
        });

        // Then
        assertThat(mergedConfig.maxBidirectionalStreamBufferSize()).isEqualTo(1024);
    }

    @Test
    void protocolMaxBufferSizeIsRespected() {
        // Given
        ServerConfig config = ServerConfig.builder()
                .maxBidirectionalStreamBufferSize(100_000)
                .build();

        // When
        ServerConfig mergedConfig = config.merge(new ApplicationProtocolSettings() {
            @Override
            public long maxBidirectionalStreamReceiverBufferSize() {
                return 5 * 1024;
            }
        });

        // Then
        assertThat(mergedConfig.maxBidirectionalStreamBufferSize()).isEqualTo(5 * 1024);
    }

    @Test
    void whenConfigValueBetweenProtocolMinAndMaxItIsUsed() {
        // Given
        ServerConfig config = ServerConfig.builder()
                .maxBidirectionalStreamBufferSize(1_000_000)
                .build();

        // When
        ServerConfig mergedConfig = config.merge(new ApplicationProtocolSettings() {
            @Override
            public int minBidirectionalStreamReceiverBufferSize() {
                return 0;
            }

            @Override
            public long maxBidirectionalStreamReceiverBufferSize() {
                return Long.MAX_VALUE;
            }
        });

        // Then
        assertThat(mergedConfig.maxBidirectionalStreamBufferSize()).isEqualTo(1_000_000);

    }
}