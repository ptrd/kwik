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
package net.luminis.quic.util;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.stream.Stream;

public class InetTools {

    public enum IPversionOption {
        UseIPv4,
        UseIPv6,
        PreferIPv4,
        PreferIPv6;
    }

    public static InetAddress lookupAddress(String hostname, IPversionOption ipVersionOption) throws UnknownHostException {
        if (hostname == null || hostname.isBlank()) {
            throw new IllegalArgumentException("hostname must be set");
        }
        if (ipVersionOption == null) {
            ipVersionOption = IPversionOption.PreferIPv4;
        }

        InetAddress[] addresses = InetAddress.getAllByName(hostname);
        switch (ipVersionOption) {
            case UseIPv4:
                return Stream.of(addresses).filter(InetTools::isIPv4).findFirst().orElseThrow(() -> new UnknownHostException("No IPv4 address found for " + hostname));
            case UseIPv6:
                return Stream.of(addresses).filter(InetTools::isIPv6).findFirst().orElseThrow(() -> new UnknownHostException("No IPv6 address found for " + hostname));
            case PreferIPv4:
                return Stream.of(addresses).sorted((a,b) -> isIPv4(a)? -1: isIPv6(a)? 1: 0).findFirst().orElseThrow(() -> new UnknownHostException("No address found for " + hostname));
            case PreferIPv6:
                return Stream.of(addresses).sorted((a,b) -> isIPv6(a)? -1: isIPv4(a)? 1: 0).findFirst().orElseThrow(() -> new UnknownHostException("No address found for " + hostname));
            default:
                // Impossible
                return null;
        }
    }

    public static boolean isIPv4(InetAddress address) {
        return address instanceof Inet4Address;
    }

    public static boolean isIPv6(InetAddress address) {
        return address instanceof Inet6Address;
    }
}
