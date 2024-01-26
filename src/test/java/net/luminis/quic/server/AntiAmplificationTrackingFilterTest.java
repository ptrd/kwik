/*
 * Copyright © 2024 Peter Doornbosch
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
package net.luminis.quic.server;

import net.luminis.quic.packet.DatagramFilter;
import net.luminis.quic.packet.PacketMetaData;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.function.Consumer;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class AntiAmplificationTrackingFilterTest {

    @Test
    void allReceivedBytesShouldBeCounted() {
        // Given
        DatagramFilter sink = mock(DatagramFilter.class);
        Consumer<Integer> counterFunction = mock(Consumer.class);
        AntiAmplificationTrackingFilter filter = new AntiAmplificationTrackingFilter(counterFunction, sink);

        // When
        filter.processDatagram(ByteBuffer.allocate(381), mock(PacketMetaData.class));

        // Then
        verify(counterFunction).accept(381);
        verify(sink).processDatagram(argThat(b -> b.remaining() == 381), any(PacketMetaData.class));
    }
}
