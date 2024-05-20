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

import net.luminis.quic.log.Logger;
import net.luminis.tls.CertificateWithPrivateKey;

import javax.security.auth.x500.X500Principal;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

public class CertificateSelector {

    private KeyStore keyManager;
    private final String keyPassword;
    private final Logger log;

    public CertificateSelector(KeyStore keyManager, String keyPassword, Logger log) {
        this.keyManager = keyManager;
        this.keyPassword = keyPassword;
        this.log = log;
    }

    public CertificateWithPrivateKey selectCertificate(List<X500Principal> authorities, boolean fallback) {
        try {
            List<String> aliases = Collections.list(keyManager.aliases());
            for (String alias: aliases) {
                X509Certificate certificate = (X509Certificate) keyManager.getCertificate(alias);
                if (authorities.contains(certificate.getIssuerX500Principal())) {
                    Key key = keyManager.getKey(alias, keyPassword.toCharArray());
                    return new CertificateWithPrivateKey(certificate, (PrivateKey) key);
                }
            }
            log.warn("None of the provided client certificates is signed by one of the requested authorities: " + authorities);

            if (fallback) {
                // Fallback to the first certificate in the key store.
                if (!aliases.isEmpty()) {
                    return new CertificateWithPrivateKey((X509Certificate) keyManager.getCertificate(aliases.get(0)),
                            (PrivateKey) keyManager.getKey(aliases.get(0), keyPassword.toCharArray()));
                }
                else {
                    log.error("No client certificate found in key store");
                }
            }
            return null;
        }
        catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            log.error("Failed to extract client certificate from key store", e);
            return null;
        }
    }
}
