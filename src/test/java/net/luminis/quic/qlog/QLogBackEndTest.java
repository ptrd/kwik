/*
 * Copyright © 2023 Peter Doornbosch
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
package net.luminis.quic.qlog;

import net.luminis.quic.qlog.event.CongestionControlMetricsEvent;
import net.luminis.quic.qlog.event.ConnectionCreatedEvent;
import net.luminis.quic.qlog.event.ConnectionTerminatedEvent;
import net.luminis.quic.qlog.event.QLogEventProcessor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.io.File;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;


class QLogBackEndTest {

    private QLogBackEnd qLogBackEnd;

    @BeforeEach
    void initObjectUnderTest() {
        qLogBackEnd = new QLogBackEnd();
    }

    @AfterEach
    void removeQlogFile() {
        File qlogFile = new File("010203.qlog");
        if (qlogFile.exists()) {
            qlogFile.delete();
        }
    }

    @Test
    void eventsWithSameCidShouldBeProcessedBySameConnectionQLog() throws InterruptedException {
        // Given
        ConnectionCreatedEvent event1 = spy(new ConnectionCreatedEvent(new byte[]{ 0x01, 0x02, 0x03 }, Instant.now()));
        qLogBackEnd.getQueue().add(event1);

        // When
        QLogEvent event2 = spy(new CongestionControlMetricsEvent(new byte[]{ 0x01, 0x02, 0x03 }, 0, 0, Instant.now()));
        qLogBackEnd.getQueue().add(event2);

        // Then
        Thread.sleep(10);

        ArgumentCaptor<QLogEventProcessor> captor1 = ArgumentCaptor.forClass(QLogEventProcessor.class);
        Mockito.verify(event1).accept(captor1.capture());

        ArgumentCaptor<QLogEventProcessor> captor2 = ArgumentCaptor.forClass(QLogEventProcessor.class);
        Mockito.verify(event2).accept(captor2.capture());

        assertThat(captor1.getValue()).isSameAs(captor2.getValue());
    }

    @Test
    void connectionTerminatedEventShouldRemoveConnectionQLog() throws InterruptedException {
        qLogBackEnd.getQueue().add(new ConnectionCreatedEvent(new byte[]{ 0x01, 0x02, 0x03 }, Instant.now()));

        QLogEvent close1 = spy(new ConnectionTerminatedEvent(new byte[]{ 0x01, 0x02, 0x03 }));
        qLogBackEnd.getQueue().add(close1);
        QLogEvent close2 = spy(new ConnectionTerminatedEvent(new byte[]{ 0x01, 0x02, 0x03 }));
        qLogBackEnd.getQueue().add(close2);

        // Then...
        Thread.sleep(10);
        // ... first close event should have removed connection, so next close event will not be processed
        Mockito.verify(close2, never()).accept(any(QLogEventProcessor.class));
    }
}
