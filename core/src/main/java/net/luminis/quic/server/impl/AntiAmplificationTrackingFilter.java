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
package net.luminis.quic.server.impl;

import net.luminis.quic.packet.BaseDatagramFilter;
import net.luminis.quic.packet.DatagramFilter;
import net.luminis.quic.packet.PacketMetaData;

import java.nio.ByteBuffer;
import java.util.function.Consumer;

/**
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation
 * "The primary defense against amplification attacks is verifying that a peer is able to receive packets at the transport
 *  address that it claims. Therefore, after receiving packets from an address that is not yet validated, an endpoint
 *  MUST limit the amount of data it sends to the unvalidated address to three times the amount of data received from
 *  that address. This limit on the size of responses is known as the anti-amplification limit."
 *
 *  https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation-during-c
 *  "For the purposes of avoiding amplification prior to address validation, servers MUST count all of the payload bytes
 *   received in datagrams that are uniquely attributed to a single connection. This includes datagrams that contain
 *   packets that are successfully processed and datagrams that contain packets that are all discarded."
 */
public class AntiAmplificationTrackingFilter extends BaseDatagramFilter {

    private final Consumer<Integer> receivedPayloadBytesCounter;

    public AntiAmplificationTrackingFilter(Consumer<Integer> receivedPayloadBytesCounter, DatagramFilter next) {
        super(next);
        this.receivedPayloadBytesCounter = receivedPayloadBytesCounter;
    }

    @Override
    public void processDatagram(ByteBuffer data, PacketMetaData metaData) {
        receivedPayloadBytesCounter.accept(data.remaining());
        next(data, metaData);
    }
}
