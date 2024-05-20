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
import net.luminis.quic.test.TestCertificates;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class CertificateSelectorTest {

    private CertificateSelector certificateSelector;

    @Test
    void whenCertIssuerDnMatchesCertShouldBeSelected() throws Exception {
        // Given
        X509Certificate endEntityCertificate1 = TestCertificates.getEndEntityCertificate1();
        PrivateKey endEntityCertificate1Key = TestCertificates.getEndEntityCertificate1Key();
        X500Principal issuer1 = endEntityCertificate1.getIssuerX500Principal();

        X509Certificate endEntityCertificate2 = TestCertificates.getEndEntityCertificate2();
        PrivateKey endEntityCertificate2Key = TestCertificates.getEndEntityCertificate2Key();
        X500Principal issuer2 = endEntityCertificate2.getIssuerX500Principal();

        KeyStore keyStore = new KeyStoreBuilder()
                .withCertificate(endEntityCertificate1, endEntityCertificate1Key)
                .withCertificate(endEntityCertificate2, endEntityCertificate2Key)
                .build();

        certificateSelector = new CertificateSelector(keyStore, "", mock(Logger.class));

        // When
        X500Principal authority = new X500Principal("CN=SampleCA2");
        var selectedForAuthority = certificateSelector.selectCertificate(List.of(authority), false);

        // Then
        assertThat(issuer1).isNotEqualTo(issuer2);
        assertThat(selectedForAuthority).isNotNull();
        assertThat(selectedForAuthority.getCertificate().getIssuerX500Principal()).isEqualTo(authority);
    }

    @Test
    void whenNoCertIssuerDnMatchesNoCertShouldBeSelected() throws Exception {
        // Given
        X509Certificate endEntityCertificate2 = TestCertificates.getEndEntityCertificate2();
        PrivateKey endEntityCertificate2Key = TestCertificates.getEndEntityCertificate2Key();
        KeyStore keyStore = new KeyStoreBuilder()
                .withCertificate(endEntityCertificate2, endEntityCertificate2Key)
                .build();
        certificateSelector = new CertificateSelector(keyStore, "", mock(Logger.class));
        X500Principal authority = new X500Principal("CN=SampleCA1");
        X500Principal issuer = endEntityCertificate2.getIssuerX500Principal();

        // When
        var certificate = certificateSelector.selectCertificate(List.of(authority), false);

        // Then
        assertThat(issuer).isNotEqualTo(authority);
        assertThat(certificate).isNull();
    }

}