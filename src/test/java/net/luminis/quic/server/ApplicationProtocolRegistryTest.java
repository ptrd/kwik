package net.luminis.quic.server;

import net.luminis.quic.QuicConnectionImpl;
import net.luminis.quic.QuicStream;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class ApplicationProtocolRegistryTest {

    @Test
    void whenCreatingConnectionCorrectFactoryIsUsed() {
        // Given
        ApplicationProtocolRegistry registry = new ApplicationProtocolRegistry();
        registry.registerApplicationProtocol("alpn", (prot, conn) -> new ApplicationProtocolConnection() {});
        registry.registerApplicationProtocol("alpn1", (prot, conn) -> new MockApplicationProtocolConnection1());
        registry.registerApplicationProtocol("alpn2", (prot, conn) -> new MockApplicationProtocolConnection2());

        // When
        ApplicationProtocolConnection applicationProtocolConnection = registry.startApplicationProtocolConnection("alpn1", mock(QuicConnectionImpl.class));

        // Then
        assertThat(applicationProtocolConnection)
                .isNotNull()
                .isInstanceOf(MockApplicationProtocolConnection1.class);
    }

    @Test
    void whenMultipleProtocolsAreRegisteredFirstMatchingIsSelected() {
        // Given
        ApplicationProtocolRegistry registry = new ApplicationProtocolRegistry();
        registry.registerApplicationProtocol("mock", (prot, conn) -> new ApplicationProtocolConnection() {});
        registry.registerApplicationProtocol("mock2", (prot, conn) -> new MockApplicationProtocolConnection1());
        registry.registerApplicationProtocol("mock1", (prot, conn) -> new MockApplicationProtocolConnection2());

        // When
        Optional<String> selectedProtocol = registry.selectSupportedApplicationProtocol(List.of("unknown", "not supported", "mock2", "dontcare", "mock1", "whatever"));

        // Then
        // https://datatracker.ietf.org/doc/html/rfc7301#section-3.2
        // "In that case, the server SHOULD select the most highly preferred protocol that it supports and that is also
        //  advertised by the client."
        assertThat(selectedProtocol).hasValue("mock2");
    }

    @Test
    void whenApplicationProtocolConnectionIsCreatedThenTheCallbackForPeerInitiatedStreamIsCalled() {
        // Given
        ApplicationProtocolRegistry registry = new ApplicationProtocolRegistry();
        registry.registerApplicationProtocol("dummy", (prot, conn) -> mock(ApplicationProtocolConnection.class));
        QuicConnectionImpl quicConnection = mock(QuicConnectionImpl.class);

        // When
        ApplicationProtocolConnection dinges = registry.startApplicationProtocolConnection("dummy", quicConnection);

        // Then
        verify(quicConnection).setPeerInitiatedStreamCallback(any(Consumer.class));
    }

    static class MockApplicationProtocolConnection1 implements ApplicationProtocolConnection {}
    static class MockApplicationProtocolConnection2 implements ApplicationProtocolConnection {}
}