/*
 * Copyright © 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.util;

import org.junit.jupiter.api.Test;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

class InetToolsTest {

    @Test
    void whenPreferenceIsIP4AndIP4IsAvailableThenIP4IsReturned() throws Exception {
        // When
        InetAddress address = InetTools.lookupAddress("www.google.com", InetTools.IPversionOption.UseIPv4);

        // Then
        assertThat(address).isInstanceOf(Inet4Address.class);
    }

    @Test
    void whenPreferenceIsIP6AndIP6IsAvailableThenIP6IsReturned() throws Exception {
        // When
        InetAddress address = InetTools.lookupAddress("www.google.com", InetTools.IPversionOption.UseIPv6);

        // Then
        assertThat(address).isInstanceOf(Inet6Address.class);
    }

    @Test
    void whenPreferenceIsIP6WithFallbackToIP4AndIP6IsAvailableThenIP6IsReturned() throws Exception {
        // When
        InetAddress address = InetTools.lookupAddress("www.google.com", InetTools.IPversionOption.PreferIPv6);

        // Then
        assertThat(address).isInstanceOf(Inet6Address.class);
    }

    @Test
    void whenPreferenceIsIP6WithFallbackToIP4AndIP6IsNotAvailableThenIP6IsReturned() throws Exception {
        // When
        InetAddress address = InetTools.lookupAddress("ipv4only.arpa", InetTools.IPversionOption.PreferIPv6);

        // Then
        assertThat(address).isInstanceOf(Inet4Address.class);
    }

    @Test
    void whenPreferenceIsIP4WithFallbackToIP6AndIP4IsAvailableThenIP4IsReturned() throws Exception {
        // When
        InetAddress address = InetTools.lookupAddress("www.google.com", InetTools.IPversionOption.PreferIPv4);

        // Then
        assertThat(address).isInstanceOf(Inet4Address.class);
    }
}