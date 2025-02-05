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
package tech.kwik.core.packet;

import tech.kwik.core.impl.TransportError;
import tech.kwik.core.log.Logger;

import java.nio.ByteBuffer;

public class DatagramPostProcessingFilter extends BaseDatagramFilter {

    private final Runnable postProcessingFunction;

    public DatagramPostProcessingFilter(Runnable postProcessingFunction, Logger log, DatagramFilter next) {
        super(next, log);
        this.postProcessingFunction = postProcessingFunction;
    }

    public DatagramPostProcessingFilter(Runnable postProcessingFunction, DatagramFilter next) {
        super(next);
        this.postProcessingFunction = postProcessingFunction;
    }

    @Override
    public void processDatagram(ByteBuffer data, PacketMetaData metaData) throws TransportError {
        next(data, metaData);
        postProcessingFunction.run();
    }
}
