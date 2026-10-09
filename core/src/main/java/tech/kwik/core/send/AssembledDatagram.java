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

import java.net.InetSocketAddress;
import java.util.List;

/**
 * Result of a packet assembly operation: a list of QUIC packets to coalesce into one UDP datagram,
 * and the minimum size that datagram must reach (used when padding is applied outside the QUIC packets).
 */
public class AssembledDatagram {

    private final List<SendItem> items;
    private final int minDatagramSize;
    private final InetSocketAddress clientAddress;

    private AssembledDatagram() {
        this.items = List.of();
        this.minDatagramSize = 0;
        this.clientAddress = null;
    }

    static AssembledDatagram empty() {
        return new AssembledDatagram();
    }

    public AssembledDatagram(List<SendItem> items, int minDatagramSize) {
        assert items != null && !items.isEmpty();
        this.items = items;
        this.minDatagramSize = minDatagramSize;
        this.clientAddress = items.get(0).getClientAddress();
        assert items.stream().allMatch(item -> item.getClientAddress().equals(clientAddress));
    }

    public List<SendItem> getItems() {
        return items;
    }

    public boolean isEmpty() {
        return items.isEmpty();
    }

    public InetSocketAddress getClientAddress() {
        return clientAddress;
    }

    /**
     * Returns the minimum UDP datagram size required, or 0 if no external padding is needed.
     */
    public int getMinDatagramSize() {
        return minDatagramSize;
    }
}
