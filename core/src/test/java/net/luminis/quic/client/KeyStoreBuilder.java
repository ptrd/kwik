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
package net.luminis.quic.client;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class KeyStoreBuilder {

    private final KeyStore keyStore;
    private int entriesCount = 0;

    public KeyStoreBuilder() throws Exception {
        keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
    }

    public KeyStore build() {
        return keyStore;
    }

    public KeyStoreBuilder withCertificate(X509Certificate certificate, PrivateKey privateKey) throws Exception {
        entriesCount++;
        keyStore.setKeyEntry("" + entriesCount, privateKey, "".toCharArray(), new X509Certificate[]{certificate});
        return this;
    }

    public KeyStoreBuilder withCertificates(PrivateKey privateKey, X509Certificate... certificates) throws Exception {
        entriesCount++;
        keyStore.setKeyEntry("" + entriesCount, privateKey, "".toCharArray(), certificates);
        return this;
    }
}
