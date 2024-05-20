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
package net.luminis.quic.test;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class TestCertificates {

    public static X509Certificate getEndEntityCertificate1() throws Exception {
        return inflateCertificate(encodedEndEntityCertificate1);
    }

    public static PrivateKey getEndEntityCertificate1Key() throws Exception {
        return inflatePrivateKey(encodedEndEntityCertificate1PrivateKey);
    }

    public static X509Certificate getEndEntityCertificate2() throws Exception {
        return inflateCertificate(encodedEndEntityCertificate2);
    }

    public static PrivateKey getEndEntityCertificate2Key() throws Exception {
        return inflatePrivateKey(encodedEndEntityCertificate2PrivateKey);
    }

    private static X509Certificate inflateCertificate(String encodedCertificate) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(encodedCertificate.getBytes())));
        return (X509Certificate) certificate;
    }

    private static PrivateKey inflatePrivateKey(String encodedPrivateKey) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encodedPrivateKey.getBytes()));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privKey = kf.generatePrivate(keySpec);
        return privKey;
    }

    // generated with: openssl req -x509 -new -nodes -key ca1.key -out ca1-cert.pem -subj='/CN=SampleCA1' -days 3650
    private static String encodedCA1Cert = "" +
            "MIIBfzCCASmgAwIBAgIUN6Hl2leUGxIljJLU4IoKCw31tUUwDQYJKoZIhvcNAQEL" +
            "BQAwFDESMBAGA1UEAwwJU2FtcGxlQ0ExMB4XDTI0MDUyMDA5NTIwNloXDTM0MDUx" +
            "ODA5NTIwNlowFDESMBAGA1UEAwwJU2FtcGxlQ0ExMFwwDQYJKoZIhvcNAQEBBQAD" +
            "SwAwSAJBAL962yDS6Qr6opKSYQgp9GNXMy+58klJWOde3l5W7qzZbiuIxw3r9aC7" +
            "6jLYG6eAxF1rAfq1/7fGBJlEO8ZbRdUCAwEAAaNTMFEwHQYDVR0OBBYEFPcYicbS" +
            "qMxJCsmX/8QX9eGMwzEyMB8GA1UdIwQYMBaAFPcYicbSqMxJCsmX/8QX9eGMwzEy" +
            "MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADQQAxBYpuu+AlIyg9ZOQ4" +
            "SRZKlghh6yX41njoLjxN+ddEiQSTs/MoHu0VzeNWbfbJyqymN/CjKXlOCC7VfRtv" +
            "bTt6";

    // generated with: openssl genrsa -out ca1.key 512
    private static String encodedCA1PrivateKey = "" +
            "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAv3rbINLpCvqikpJh" +
            "CCn0Y1czL7nySUlY517eXlburNluK4jHDev1oLvqMtgbp4DEXWsB+rX/t8YEmUQ7" +
            "xltF1QIDAQABAkBrg1ISphoP/hbWcbZl3RjJxqaI/8FZAQQYNZ5qHim5hwo1YnnF" +
            "79ojPsFOeUx3wwD7OeV/AlRI0CN+2ldzME5BAiEA94Qs+qIp1v/UOcxhp7ej57VY" +
            "6ExU0iDpJ/QivdmRyWkCIQDGCv2Ugy2FDeZHqZtDIkavZLGoo6AdeBw8svLH+jq/" +
            "jQIgQJ67d3va3IzSBXz8ieMB4b6QxaUYB/wboxiz8UjaLPECICdHKr/3vGF1PkTc" +
            "SKTp+Wbz66Bsw2bU2ZTYUPqEkH5JAiEA7JmGu/FKx+om5s4uhG/id60BWc9MlYPZ" +
            "mw59vf0oexA=";

    // generated with: openssl req -x509 -new -nodes -key ca2.key -out ca2-cert.pem -subj='/CN=SampleCA2' -days 3650
    private static String encodedCA2Cert = "" +
            "MIIBfzCCASmgAwIBAgIUP1vftaLSi8iY3ZrU9gOS/GCjT/MwDQYJKoZIhvcNAQEL" +
            "BQAwFDESMBAGA1UEAwwJU2FtcGxlQ0EyMB4XDTI0MDUyMDE3NDM0MFoXDTM0MDUx" +
            "ODE3NDM0MFowFDESMBAGA1UEAwwJU2FtcGxlQ0EyMFwwDQYJKoZIhvcNAQEBBQAD" +
            "SwAwSAJBAO11I3lCt0dsmrE5m/QANuGFoUL4nEXHetoewv5/s/EqSccepxAUWobd" +
            "QdX1wXtKaKG/MdyP+DgBuBN+znQFzCECAwEAAaNTMFEwHQYDVR0OBBYEFNXgaaYm" +
            "JTlw/YdsYSxgzdLL/W/NMB8GA1UdIwQYMBaAFNXgaaYmJTlw/YdsYSxgzdLL/W/N" +
            "MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADQQDfv3hJg575F7Ubq3AT" +
            "kfbpZOjtABFhto6CqDnn4xOnjVxERplWBNHi7fghSwuTLd5cPhr1swCybnMKRXk9" +
            "Hr8G";

    // generated with: openssl genrsa -out ca2.key 512
    private static String encodedCA2PrivateKey = "" +
            "MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEA7XUjeUK3R2yasTmb" +
            "9AA24YWhQvicRcd62h7C/n+z8SpJxx6nEBRaht1B1fXBe0poob8x3I/4OAG4E37O" +
            "dAXMIQIDAQABAkEAyVoO3oAoEbSR573F9D1KTCmX+MX/HVxtXA/BoTSATPnAm4XA" +
            "IvS+JXocbP4Y4Wuv05hyiqdKbiqIDsmJwyOrkQIhAPyRcgqgUyBoIqn+a7rWtVRK" +
            "GLhxdVxPVaVmBlL3OfibAiEA8K8hlZjXiVgNfEL0TTgCsXgGQ5k8TmG2MoM6yasP" +
            "A/MCIQDcuFq6UJv0sSzB9La+5E45KDvsTDLtBePqFHwoWyfNSwIgGJsO5+hUQKpL" +
            "1qRRrYNIYzROD6Me0zSSF9/qpqtiQZkCIQDhyaeVv3TxJMquKUeYIvItbncp89vp" +
            "tlhDd+dug3wXFw==";

    // generated with:
    // - openssl req -key ee1.key -new -out ee1-cert.csr -subj='/CN=endentity1'
    // - openssl x509 -req -in ee1-cert.csr -CAkey ca1.key -CA ca1-cert.pem -out ee1-cert.pem -days 3650 -CAcreateserial
    private static String encodedEndEntityCertificate1 = "" +
            "MIIBbzCCARmgAwIBAgIUIB1oAMWScq46DtnMcr9yLhX9mpUwDQYJKoZIhvcNAQEL" +
            "BQAwFDESMBAGA1UEAwwJU2FtcGxlQ0ExMB4XDTI0MDUyMDEwMDYzMFoXDTM0MDUx" +
            "ODEwMDYzMFowFTETMBEGA1UEAwwKZW5kZW50aXR5MTBcMA0GCSqGSIb3DQEBAQUA" +
            "A0sAMEgCQQCn0UztBH+AxfgVL1BsswpvzIEzEIU6B0asG5mH941NLqocER4p579r" +
            "AceYYzzZ3HZUj8TkM90TnPH4b5ZYCq1jAgMBAAGjQjBAMB0GA1UdDgQWBBTQi6gH" +
            "OhvrBkp8QBQfRY7dovH9aTAfBgNVHSMEGDAWgBT3GInG0qjMSQrJl//EF/XhjMMx" +
            "MjANBgkqhkiG9w0BAQsFAANBAKcKcSS/aQ+Lm0HVz20XSF+qy/tuJbcdHIC1iJa7" +
            "oSS1mdHKe6++JxwTs7DcVmEWCoLGf/0ZHS8IDaMSeY83JNg=";

    // generated with: openssl genrsa -out ee1.key 512
    private static String encodedEndEntityCertificate1PrivateKey = "" +
            "MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEAp9FM7QR/gMX4FS9Q" +
            "bLMKb8yBMxCFOgdGrBuZh/eNTS6qHBEeKee/awHHmGM82dx2VI/E5DPdE5zx+G+W" +
            "WAqtYwIDAQABAkB/RlW5TLgGyh4kswWj6wX3VHqIZ/ci03HeBfCjFjSsW4ScdMbK" +
            "zt/zvDVuvWGSQyNNmiAIOZ/74/SyJB4/eUiBAiEA3vGuUg6sDDdl6IVKVpEncSxU" +
            "3c2IVY9eecNq/wKSJssCIQDAsy0CalDIPkzrLGHJpiywWww7F1yp+dHaXVo1/d+o" +
            "yQIgTXEsOWrJTrELoDp0uR9Q0RoyHJ3hhr73dVpxV0WgWQMCIHWATB++6EdSBeEZ" +
            "DP/CvllDC3A0zKIw3Q+EAPAPQARRAiBr6a4IpyF8UsjWWGXBiXX2eMILo0wP3bXo" +
            "BijIu5IkCw==";

    // generated with:
    // - openssl req -key ee2.key -new -out ee2-cert.csr -subj='/C=NL/O=Kwik/OU=Kwik Dev/CN=endentity2'
    // - openssl x509 -req -in ee2-cert.csr -CAkey ca2.key -CA ca2-cert.pem -out ee2-cert.pem -days 3650
    private static String encodedEndEntityCertificate2 = "" +
            "MIIBnjCCAUigAwIBAgIUXJu9pLTwEF9XCf/shg7tSVwymIowDQYJKoZIhvcNAQEL" +
            "BQAwFDESMBAGA1UEAwwJU2FtcGxlQ0EyMB4XDTI0MDUyMDE3NDg0NFoXDTM0MDUx" +
            "ODE3NDg0NFowRDELMAkGA1UEBhMCTkwxDTALBgNVBAoMBEt3aWsxETAPBgNVBAsM" +
            "CEt3aWsgRGV2MRMwEQYDVQQDDAplbmRlbnRpdHkyMFwwDQYJKoZIhvcNAQEBBQAD" +
            "SwAwSAJBAMzKsq/sUjaBB4awZA7lzGTYkPKx8Kg8AEo9No/XUEv16nh3o0UMCQoo" +
            "F6EXzEGdwNoZE+cPKsLsdF5etI20VrUCAwEAAaNCMEAwHQYDVR0OBBYEFKGicTJk" +
            "afj0eUhd0nxsv0r1Z0QAMB8GA1UdIwQYMBaAFNXgaaYmJTlw/YdsYSxgzdLL/W/N" +
            "MA0GCSqGSIb3DQEBCwUAA0EA5oCu0wL9jIARTUgR0z9wjtkYYIqLn0CxevWBj2sA" +
            "nAdaa5I6GJIssu7fGkN6ylgduA5kxZVvCloQzFf20DU+LA==";

    // generated with: openssl genrsa -out ee2.key 512
    private static String encodedEndEntityCertificate2PrivateKey = "" +
            "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAzMqyr+xSNoEHhrBk" +
            "DuXMZNiQ8rHwqDwASj02j9dQS/XqeHejRQwJCigXoRfMQZ3A2hkT5w8qwux0Xl60" +
            "jbRWtQIDAQABAkB1IL2ARs5io/uU+k/QAXiceQy18jWtUtvrmgUZ0dD4EAEV1JPc" +
            "3YGhyRi4BMPFcIvgAPATe7lT5+k0TVXdwvshAiEA8rCgYwhrj7ceT/IVTt4/YXdU" +
            "KAcOkDHyxqjFMwVvAY0CIQDYBfr1gmWuD9JP44i8r1x6hgaWyXVr3C7atY/R+rtb" +
            "yQIgN7pZSgRf9qNdAYycWfzs3uuw1nQwYuolTnrotXuU7u0CIAFtYLAYkXVp81jF" +
            "xxSAEBtbIVYDtLvms4SMaIvZnT1JAiEAx9gnArn2QHXLHUt8iGBPj9PvkhrkA75k" +
            "U4kfPF1uleg=";

}
