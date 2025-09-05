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
package tech.kwik.core.client;

import tech.kwik.agent15.engine.CertificateWithPrivateKey;
import tech.kwik.core.log.Logger;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;
import java.security.Key;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;


public class CertificateSelector {

    private X509ExtendedKeyManager keyManager;
    private final Logger log;

    public CertificateSelector(X509ExtendedKeyManager keyManager, Logger log) {
        this.keyManager = keyManager;
        this.log = log;
    }

    public CertificateWithPrivateKey selectCertificate(List<X500Principal> authorities, boolean fallback) {
        CertificateWithPrivateKey result = null;
            Principal[] issuers = authorities.toArray(new Principal[0]);
            String clientAlias = keyManager.chooseEngineClientAlias(new String[]{"RSA", "EC"}, issuers, null);
            if (clientAlias != null) {
                X509Certificate certificate = keyManager.getCertificateChain(clientAlias)[0];
                Key key = keyManager.getPrivateKey(clientAlias);
                result = new CertificateWithPrivateKey(certificate, (PrivateKey) key);
            }
            else {
                log.warn("No client certificate found in key store signed by one of the requested authorities: " + authorities);
            }

            if (result == null && fallback) {
                // Fallback to the first certificate in the key store.
                String[] clientAliases = keyManager.getClientAliases("RSA", null);
                if (clientAliases == null || clientAliases.length == 0) {
                    clientAliases = keyManager.getClientAliases("EC", null);
                }
                if (clientAliases != null && clientAliases.length > 0) {
                    String alias = clientAliases[0];
                    result = new CertificateWithPrivateKey(keyManager.getCertificateChain(alias)[0], keyManager.getPrivateKey(alias));
                }
                else {
                    log.error("No client certificate found in key store");
                }
            }

        return result;
    }
}
