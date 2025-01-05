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
package net.luminis.quic.client;

import net.luminis.quic.log.Logger;
import tech.kwik.agent15.engine.CertificateWithPrivateKey;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;


public class CertificateSelector {

    private KeyStore keyStore;
    private final String keyPassword;
    private final Logger log;

    public CertificateSelector(KeyStore keyManager, String keyPassword, Logger log) {
        this.keyStore = keyManager;
        this.keyPassword = keyPassword;
        this.log = log;
    }

    public CertificateWithPrivateKey selectCertificate(List<X500Principal> authorities, boolean fallback) {
        CertificateWithPrivateKey result = null;
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, keyPassword.toCharArray());
            KeyManager keyManager = keyManagerFactory.getKeyManagers()[0];
            if (keyManager instanceof X509ExtendedKeyManager) {
                X509ExtendedKeyManager x509KeyManager = (X509ExtendedKeyManager) keyManager;

                Principal[] issuers = authorities.toArray(new Principal[0]);
                String clientAlias = x509KeyManager.chooseEngineClientAlias(new String[]{"RSA", "EC"}, issuers, null);
                if (clientAlias != null) {
                    X509Certificate certificate = x509KeyManager.getCertificateChain(clientAlias)[0];
                    Key key = x509KeyManager.getPrivateKey(clientAlias);
                    result = new CertificateWithPrivateKey(certificate, (PrivateKey) key);
                }
                else {
                    log.warn("No client certificate found in key store signed by one of the requested authorities: " + authorities);
                }
            }
            else {
                log.warn("Key manager is not an X509ExtendedKeyManager");
            }

            if (result == null && fallback) {
                // Fallback to the first certificate in the key store.
                if (!Collections.list(keyStore.aliases()).isEmpty()) {
                    String alias = Collections.list(keyStore.aliases()).get(0);
                    result = new CertificateWithPrivateKey((X509Certificate) keyStore.getCertificate(alias),
                            (PrivateKey) keyStore.getKey(alias, keyPassword.toCharArray()));
                }
                else {
                    log.error("No client certificate found in key store");
                }
            }
        }
        catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            log.error("Failed to extract client certificate from key store", e);
        }
        return result;
    }
}
