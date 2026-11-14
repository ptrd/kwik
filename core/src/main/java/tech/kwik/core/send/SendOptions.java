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
 * Options that influence how a datagram is assembled and sent. Instances are immutable.
 */
public class SendOptions {

    private static final SendOptions DEFAULT = new SendOptions(false);
    private static final SendOptions NO_PADDING = new SendOptions(true);

    private final boolean doNotPad;

    private SendOptions(boolean doNotPad) {
        this.doNotPad = doNotPad;
    }

    public static SendOptions getDefault() {
        return DEFAULT;
    }

    /**
     * Options indicating that the datagram must not be padded, e.g. because padding could exceed the
     * anti-amplification limit of the path.
     */
    public static SendOptions noPadding() {
        return NO_PADDING;
    }

    /**
     * Neutral starting point for merging the options of multiple packets that are coalesced into one datagram.
     */
    public static SendOptions empty() {
        return DEFAULT;
    }

    /**
     * Combines these options with the given options, for when packets with different options end up in one datagram.
     * Restrictions win: if either one forbids padding, the result forbids padding.
     */
    public SendOptions merge(SendOptions sendOptions) {
        if (sendOptions == null || sendOptions == this) {
            return this;
        }
        return (doNotPad || sendOptions.doNotPad) ? NO_PADDING : DEFAULT;
    }

    public boolean doNotPad() {
        return doNotPad;
    }

    @Override
    public String toString() {
        return "SendOptions[" + (doNotPad ? "noPadding" : "default") + "]";
    }
}
