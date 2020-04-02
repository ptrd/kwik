/*
 * Copyright © 2019, 2020 Peter Doornbosch
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

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


class VariableLengthIntegerTest {

    @Test
    void parseSingleByteInteger() {
        // Taken from https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-16
        // "and the single byte 25 decodes to 37"
        int value = VariableLengthInteger.parse(wrap((byte) 0x25));

        assertThat(value).isEqualTo(37);
    }

    @Test
    void parseSingleByteIntegerFromStream() throws IOException {
        // Taken from https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-16
        // "and the single byte 25 decodes to 37"
        int value = VariableLengthInteger.parse(wrapAsStream((byte) 0x25));

        assertThat(value).isEqualTo(37);
    }

    @Test
    void parseTwoByteInteger() {
        // Taken from https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-16
        // "the two byte sequence 7b bd decodes to 15293; "
        int value = VariableLengthInteger.parse(wrap((byte) 0x7b, (byte) 0xbd));

        assertThat(value).isEqualTo(15293);
    }

    @Test
    void parseTwoByteIntegerFromStream() throws IOException {
        // Taken from https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-16
        // "the two byte sequence 7b bd decodes to 15293; "
        int value = VariableLengthInteger.parse(wrapAsStream((byte) 0x7b, (byte) 0xbd));

        assertThat(value).isEqualTo(15293);
    }

    @Test
    void parseSingleByteIntegerEncodedInTwoByte() {
        // Taken from https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-16
        // "(as does the two byte sequence 40 25)"
        int value = VariableLengthInteger.parse(wrap((byte) 0x40, (byte) 0x25));

        assertThat(value).isEqualTo(37);
    }

    @Test
    void parseFourByteInteger() {
        // Taken from https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-16
        // "the four byte sequence 9d 7f 3e 7d decodes to 494878333;"
        int value = VariableLengthInteger.parse(wrap((byte) 0x9d, (byte) 0x7f, (byte) 0x3e, (byte) 0x7d));

        assertThat(value).isEqualTo(494878333);
    }

    @Test
    void parseFourByteIntegerFromStream() throws IOException {
        // Taken from https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-16
        // "the four byte sequence 9d 7f 3e 7d decodes to 494878333;"
        int value = VariableLengthInteger.parse(wrapAsStream((byte) 0x9d, (byte) 0x7f, (byte) 0x3e, (byte) 0x7d));

        assertThat(value).isEqualTo(494878333);
    }

    @Test
    void parseIncompleteFourByteIntegerFromStream() throws IOException {
        assertThatThrownBy(
                () -> VariableLengthInteger.parse(wrapAsStream((byte) 0x9d, (byte) 0x7f, (byte) 0x3e)))
                .isInstanceOf(EOFException.class);
    }

    @Test
    void parseMaxInteger() {
        int value = VariableLengthInteger.parse(wrap((byte) 0xc0, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff));

        assertThat(value).isEqualTo(Integer.MAX_VALUE);
    }

    @Test
    void parseValueGreaterThanMaxInteger() {
        byte[] rawBytes = { (byte) 0xc0, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };

        assertThatThrownBy(
                () -> VariableLengthInteger.parse(wrap(rawBytes)))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void parseLongValueGreaterThanMaxInteger() {
        // Taken from https://tools.ietf.org/html/draft-ietf-quic-transport-20#section-16
        // "the eight byte sequence c2 19 7c 5e ff 14 e8 8c (in
        //   hexadecimal) decodes to the decimal value 151288809941952652;"
        byte[] rawBytes = { (byte) 0xc2, (byte) 0x19, (byte) 0x7c, (byte) 0x5e,
                (byte) 0xff, (byte) 0x14, (byte) 0xe8, (byte) 0x8c };

        long value = VariableLengthInteger.parseLong(wrap(rawBytes));
        assertThat(value).isEqualTo(151288809941952652L);
    }

    @Test
    void parseMaxLong() {
        byte[] rawBytes = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };

        long value = VariableLengthInteger.parseLong(wrap(rawBytes));
        assertThat(value).isEqualTo(4611686018427387903L);
    }

    @Test
    void encodeSingleByteInteger() {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        int encodedSize = VariableLengthInteger.encode(37, buffer);

        assertThat(encodedSize).isEqualTo(1);
        assertThat(buffer.position()).isEqualTo(1);
        buffer.flip();
        assertThat(buffer.get()).isEqualTo((byte) 0x25);
    }

    @Test
    void encodeTwoByteInteger() {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        int encodedSize = VariableLengthInteger.encode(15293, buffer);

        assertThat(encodedSize).isEqualTo(2);
        assertThat(buffer.position()).isEqualTo(2);
        buffer.flip();
        assertThat(buffer.get()).isEqualTo((byte) 0x7b);
        assertThat(buffer.get()).isEqualTo((byte) 0xbd);
    }

    @Test
    void encodeFourByteInteger() {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        int encodedSize = VariableLengthInteger.encode(494878333, buffer);

        assertThat(encodedSize).isEqualTo(4);
        assertThat(buffer.position()).isEqualTo(4);
        buffer.flip();
        assertThat(buffer.get()).isEqualTo((byte) 0x9d);
        assertThat(buffer.get()).isEqualTo((byte) 0x7f);
        assertThat(buffer.get()).isEqualTo((byte) 0x3e);
        assertThat(buffer.get()).isEqualTo((byte) 0x7d);
    }

    @Test
    void encodeMaxInteger() {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        int encodedSize = VariableLengthInteger.encode(Integer.MAX_VALUE, buffer);

        assertThat(encodedSize).isEqualTo(8);
        assertThat(buffer.position()).isEqualTo(8);
        buffer.flip();
        assertThat(buffer.get()).isEqualTo((byte) 0xc0);
        assertThat(buffer.get()).isEqualTo((byte) 0x00);
        assertThat(buffer.get()).isEqualTo((byte) 0x00);
        assertThat(buffer.get()).isEqualTo((byte) 0x00);
        assertThat(buffer.get()).isEqualTo((byte) 0x7f);
        assertThat(buffer.get()).isEqualTo((byte) 0xff);
        assertThat(buffer.get()).isEqualTo((byte) 0xff);
        assertThat(buffer.get()).isEqualTo((byte) 0xff);
    }

    @Test
    void encodeLong() {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        // Taken from https://tools.ietf.org/html/draft-ietf-quic-transport-20#section-16
        int encodedSize = VariableLengthInteger.encode(151288809941952652L, buffer);

        assertThat(encodedSize).isEqualTo(8);
        assertThat(buffer.position()).isEqualTo(8);
        buffer.flip();
        assertThat(buffer.get()).isEqualTo((byte) 0xc2);
        assertThat(buffer.get()).isEqualTo((byte) 0x19);
        assertThat(buffer.get()).isEqualTo((byte) 0x7c);
        assertThat(buffer.get()).isEqualTo((byte) 0x5e);
        assertThat(buffer.get()).isEqualTo((byte) 0xff);
        assertThat(buffer.get()).isEqualTo((byte) 0x14);
        assertThat(buffer.get()).isEqualTo((byte) 0xe8);
        assertThat(buffer.get()).isEqualTo((byte) 0x8c);
    }

    @Test
    void parseLong() {
        long value = VariableLengthInteger.parseLong(
                // Taken from https://tools.ietf.org/html/draft-ietf-quic-transport-20#section-16
                wrap(   (byte) 0xc2, (byte) 0x19, (byte) 0x7c, (byte) 0x5e,
                        (byte) 0xff, (byte) 0x14, (byte) 0xe8, (byte) 0x8c)  );

        assertThat(value).isEqualTo(151288809941952652L);
    }

    @Test
    void parseLongFromStream() throws IOException {
        long value = VariableLengthInteger.parseLong(
                // Taken from https://tools.ietf.org/html/draft-ietf-quic-transport-20#section-16
                wrapAsStream(   (byte) 0xc2, (byte) 0x19, (byte) 0x7c, (byte) 0x5e,
                        (byte) 0xff, (byte) 0x14, (byte) 0xe8, (byte) 0x8c)  );

        assertThat(value).isEqualTo(151288809941952652L);
    }

    private ByteBuffer wrap(byte... bytes) {
        return ByteBuffer.wrap(bytes);
    }

    private InputStream wrapAsStream(byte... bytes) {
        return new ByteArrayInputStream(bytes);
    }

}
