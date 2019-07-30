/*
 * Copyright © 2019 Peter Doornbosch
 *
 * This file is part of Kwik, a QUIC client Java library
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
package net.luminis.quic;

import net.luminis.tls.Message;
import net.luminis.tls.TlsProtocolException;
import net.luminis.tls.TlsState;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.internal.util.reflection.FieldSetter;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CryptoStreamTest {

    private CryptoStream cryptoStream;
    private TlsMessageParser messageParser;

    @BeforeEach
    void prepareObjectUnderTest() throws Exception {
        cryptoStream = new CryptoStream(Version.getDefault(), null, EncryptionLevel.Handshake, null, new TlsState(), mock(Logger.class));
        messageParser = mock(TlsMessageParser.class);
        FieldSetter.setField(cryptoStream, cryptoStream.getClass().getDeclaredField("tlsMessageParser"), messageParser);
    }

    @Test
    void parseSingleMessageInSingleFrame() throws Exception {
        setParseFunction(buffer -> {
            buffer.position(buffer.limit());
            return new String(buffer.array());
        });

        cryptoStream.add(new CryptoFrame(Version.getDefault(), "first crypto frame".getBytes()));

        assertThat(cryptoStream.getTlsMessages().isEmpty()).isFalse();
        assertThat(cryptoStream.getTlsMessages()).contains(new MockTlsMessage("first crypto frame"));
    }

    @Test
    void parserWaitsForAllFramesNeededToParseWholeMessage() throws Exception {
        setParseFunction(buffer -> {
            // Simulate message can only be parsed when all 3 frames are present
            if (buffer.limit() > 23) {
                buffer.position(buffer.limit());
                return new String(buffer.array());
            }
            else {
                throw new BufferUnderflowException();
            }

        });

        cryptoStream.add(new CryptoFrame(Version.getDefault(), 0, "first frame".getBytes()));
        assertThat(cryptoStream.getTlsMessages()).isEmpty();

        cryptoStream.add(new CryptoFrame(Version.getDefault(), 11, "second frame".getBytes()));
        assertThat(cryptoStream.getTlsMessages()).isEmpty();

        cryptoStream.add(new CryptoFrame(Version.getDefault(), 23, "last crypto frame".getBytes()));
        assertThat(cryptoStream.getTlsMessages()).contains(new MockTlsMessage("first framesecond framelast crypto frame"));
    }

    @Test
    void parserWaitsForAllOutOfOrderFramesNeededToParseWholeMessage() throws Exception {
        setParseFunction(buffer -> {
            // Simulate message can only be parsed when all 3 frames are present
            if (buffer.limit() > 23) {
                buffer.position(buffer.limit());
                return new String(buffer.array());
            }
            else {
                throw new BufferUnderflowException();
            }

        });

        cryptoStream.add(new CryptoFrame(Version.getDefault(), 23, "last crypto frame".getBytes()));
        assertThat(cryptoStream.getTlsMessages()).isEmpty();

        cryptoStream.add(new CryptoFrame(Version.getDefault(), 0, "first frame".getBytes()));
        assertThat(cryptoStream.getTlsMessages()).isEmpty();

        cryptoStream.add(new CryptoFrame(Version.getDefault(), 11, "second frame".getBytes()));
        assertThat(cryptoStream.getTlsMessages()).contains(new MockTlsMessage("first framesecond framelast crypto frame"));
    }

    @Test
    void handleRetransmittedFramesWithDifferentSegmentation() throws Exception {
        setParseFunction(buffer -> {
            // Simulate message can only be parsed when all 3 frames are present
            if (buffer.limit() > 23) {
                buffer.position(buffer.limit());
                return new String(buffer.array());
            }
            else {
                throw new BufferUnderflowException();
            }

        });

        cryptoStream.add(new CryptoFrame(Version.getDefault(), 23, "last crypto frame".getBytes()));
        assertThat(cryptoStream.getTlsMessages()).isEmpty();

        cryptoStream.add(new CryptoFrame(Version.getDefault(), 0, "first frame".getBytes()));
        assertThat(cryptoStream.getTlsMessages()).isEmpty();

        // Simulate second frame is never received, but all crypto content is retransmitted in different frames.
        cryptoStream.add(new CryptoFrame(Version.getDefault(), 0, "first framesecond ".getBytes()));
        assertThat(cryptoStream.getTlsMessages()).isEmpty();

        cryptoStream.add(new CryptoFrame(Version.getDefault(), 18, "framelast crypto frame".getBytes()));
        assertThat(cryptoStream.getTlsMessages()).contains(new MockTlsMessage("first framesecond framelast crypto frame"));
    }


    private void setParseFunction(Function<ByteBuffer, String> parseFunction) throws Exception {
        when(messageParser.parse(any(ByteBuffer.class), any(TlsState.class))).thenAnswer(new Answer<Message>() {
            @Override
            public Message answer(InvocationOnMock invocation) throws Throwable {
                ByteBuffer buffer = invocation.getArgument(0);
                return new MockTlsMessage(parseFunction.apply(buffer));
            }
        });
    }

    static class MockTlsMessage extends Message {
        String contents;

        public MockTlsMessage(String contents) {
            this.contents = contents;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            MockTlsMessage that = (MockTlsMessage) o;
            return Objects.equals(contents, that.contents);
        }

        @Override
        public int hashCode() {
            return Objects.hash(contents);
        }

        @Override
        public String toString() {
            return "Message: " + contents;
        }
    }

}