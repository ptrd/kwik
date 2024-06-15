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
package net.luminis.quic.test;

public class ByteUtils {

    /**
     * Converts a hexadecimal string to a byte array.
     *
     * @param hexString the hexadecimal string to convert
     * @return the byte array represented by the hexadecimal string
     * @throws IllegalArgumentException if the input string is not a valid hexadecimal string
     */
    public static byte[] hexToBytes0(String hexString) throws IllegalArgumentException {
        if (hexString == null || hexString.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hexadecimal string");
        }

        int length = hexString.length();
        byte[] byteArray = new byte[length / 2];

        for (int i = 0; i < length; i += 2) {
            String hexByte = hexString.substring(i, i + 2);
            byteArray[i / 2] = (byte) Integer.parseInt(hexByte, 16);
        }

        return byteArray;
    }

    /**
     * Converts a hexadecimal string to a byte array.
     *
     * @param hexString the hexadecimal string to convert
     * @return the byte array represented by the hexadecimal string
     * @throws IllegalArgumentException if the input string is not a valid hexadecimal string
     */
    public static byte[] hexToBytes(String hexString) throws IllegalArgumentException {
        if (hexString == null) {
            throw new IllegalArgumentException("Input string cannot be null");
        }

        hexString = hexString.replaceAll("\\s", "");

        if (hexString.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hexadecimal string length");
        }

        int length = hexString.length();
        byte[] byteArray = new byte[length / 2];

        for (int i = 0; i < length; i += 2) {
            try {
                String hexByte = hexString.substring(i, i + 2);
                byteArray[i / 2] = (byte) Integer.parseInt(hexByte, 16);
            }
            catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid character in hexadecimal string");
            }
        }

        return byteArray;
    }
}

