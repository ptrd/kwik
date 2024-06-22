package net.luminis.quic.server;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ServerConfigTest {

    @Test
    void whenMaxConcurrentUnidirectionalStreamsNotSetInProtocolSettingsServerConfigValueShouldBeUsed() {
        // Given
        ServerConnectionConfig config = ServerConnectionConfig.builder()
                .maxOpenPeerInitiatedUnidirectionalStreams(10)
                .build();

        // When
        ServerConnectionConfig mergedConfig = config.merge(new ApplicationProtocolSettings() {});

        // Then
        assertThat(mergedConfig.maxOpenPeerInitiatedUnidirectionalStreams()).isEqualTo(10);
    }

    @Test
    void whenMaxConcurrentUnidirectionalStreamsIsSetInProtocolSettingsItShouldBeUsed() {
        // Given
        ServerConnectionConfig config = ServerConnectionConfig.builder()
                .maxOpenPeerInitiatedUnidirectionalStreams(10)
                .build();

        // When
        ServerConnectionConfig mergedConfig = config.merge(new ApplicationProtocolSettings() {
            @Override
            public int maxConcurrentPeerInitiatedUnidirectionalStreams() {
                return 3;
            }
        });

        // Then
        assertThat(mergedConfig.maxOpenPeerInitiatedUnidirectionalStreams()).isEqualTo(3);
    }

    @Test
    void protocolMinBufferSizeIsRespected() {
        // Given
        ServerConnectionConfig config = ServerConnectionConfig.builder()
                .maxConnectionBufferSize(100)
                .maxBidirectionalStreamBufferSize(100)
                .build();

        // When
        ServerConnectionConfig mergedConfig = config.merge(new ApplicationProtocolSettings() {
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
        ServerConnectionConfig config = ServerConnectionConfig.builder()
                .maxConnectionBufferSize(100_000)
                .maxBidirectionalStreamBufferSize(100_000)
                .build();

        // When
        ServerConnectionConfig mergedConfig = config.merge(new ApplicationProtocolSettings() {
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
        ServerConnectionConfig config = ServerConnectionConfig.builder()
                .maxConnectionBufferSize(10_000_000)
                .maxBidirectionalStreamBufferSize(1_000_000)
                .build();

        // When
        ServerConnectionConfig mergedConfig = config.merge(new ApplicationProtocolSettings() {
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

    @Test
    void connectionBufferCantBeLessThenUnidirectionalStreamBufferSize() {
        // Given
        ServerConnectionConfig.Builder builder = ServerConnectionConfig.builder()
                .maxConnectionBufferSize(100)
                .maxUnidirectionalStreamBufferSize(1000);

        // When
        assertThatThrownBy(builder::build).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void connectionBufferCantBeLessThenBidirectionalStreamBufferSize() {
        // Given
        ServerConnectionConfig.Builder builder = ServerConnectionConfig.builder()
                .maxConnectionBufferSize(100)
                .maxBidirectionalStreamBufferSize(1000);

        // When
        assertThatThrownBy(builder::build).isInstanceOf(IllegalArgumentException.class);
    }
}