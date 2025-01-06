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
package tech.kwik.interop;


import tech.kwik.core.KwikVersion;

import java.util.Arrays;

public class InteropRunner {

    public static void main(String[] args) throws Exception {
        if (args.length > 0) {
            String[] otherArgs = Arrays.copyOfRange(args, 1, args.length);
            if (args[0].equals("-s")) {
                InteropServer.main(otherArgs);
            }
            else if (args[0].equals("-c")) {
                InteropClient.main(otherArgs);
            }
            else if (args[0].equals("-v")) {
                System.out.println(KwikVersion.getVersion());
            }
            else {
                System.err.println("Unknown command: " + args[0]);
            }
        }
        else {
            System.err.println("Usage: -s|-c [args]");
        }
    }
}
