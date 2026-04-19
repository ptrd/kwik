/*
 * Copyright © 2026 Peter Doornbosch
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
package tech.kwik.core.send;

/**
 * Determines how padding is added to reach the 1200-byte minimum UDP datagram size required for
 * Initial packets (RFC 9000, section 14.1).
 * Configured via the system property {@code tech.kwik.padding-mode}:
 * <ul>
 *   <li>{@code inside}  (default) — adds PADDING frames inside the QUIC packet</li>
 *   <li>{@code outside} — appends raw zero bytes in the UDP datagram after the QUIC packet bytes</li>
 * </ul>
 */
public enum PaddingMode {
    INSIDE,
    OUTSIDE
}
