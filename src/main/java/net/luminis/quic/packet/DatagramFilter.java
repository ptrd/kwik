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
package net.luminis.quic.packet;

import java.nio.ByteBuffer;

public interface DatagramFilter {

    /**
     * Filters an incoming datagram and passes it to the next filter in the chain (unless it intentionally drops the
     * datagram). The filter should not modify the state of the buffer, so if it reads from it, it should restore the
     * position to its original value. Also, it should not depend on a previous mark being set nor try to pass a mark
     * to the next filter in the chain. So ByteBuffer.mark and ByteBuffer.reset() can be used, but only in this scope.
     * @param data
     * @param metaData
     */
    void processDatagram(ByteBuffer data, PacketMetaData metaData);
}
