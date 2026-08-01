/*
 * Copyright © 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.core.test;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Test certificates and keys, used by unit tests that exercise certificate selection and TLS handshakes.
 *
 * <p>The RSA keys are 2048 bit; smaller keys (the original fixtures used 512 bit) are rejected by the JDK's default
 * algorithm constraints ({@code jdk.certpath.disabledAlgorithms} contains {@code RSA keySize < 1024}), which as of
 * JDK 26 are also enforced during client certificate (alias) selection by the {@code SunX509} key manager.
 *
 * <p>Each field's Javadoc lists the exact {@code openssl} commands used to generate it, so the fixtures can be
 * regenerated. Certificates are stored as base64-encoded DER (the body of the PEM file). Private keys are stored as
 * base64-encoded PKCS#8 DER, because {@link PKCS8EncodedKeySpec} (used by {@link #inflatePrivateKey}) expects PKCS#8;
 * {@code openssl genrsa} emits a traditional (PKCS#1) key, hence the additional {@code openssl pkcs8} conversion step.
 *
 * <p>Certificate hierarchy:
 * <pre>
 *   SampleCA1 (self-signed root)
 *     ├─ endentity1
 *     └─ SubCA (intermediate)
 *          └─ endentity1_1
 *   SampleCA2 (self-signed root)
 *     └─ endentity2
 *   SampleECRoot (self-signed, EC secp256r1)
 * </pre>
 */
public class TestCertificates {

    public static X509Certificate getEndEntityCertificate1() throws Exception {
        return inflateCertificate(encodedEndEntityCertificate1);
    }

    public static PrivateKey getEndEntityCertificate1Key() throws Exception {
        return inflatePrivateKey(encodedEndEntityCertificate1PrivateKey, "RSA");
    }

    public static X509Certificate getEndEntityCertificate2() throws Exception {
        return inflateCertificate(encodedEndEntityCertificate2);
    }

    public static PrivateKey getEndEntityCertificate2Key() throws Exception {
        return inflatePrivateKey(encodedEndEntityCertificate2PrivateKey, "RSA");
    }

    public static X509Certificate getSubCACertificate1() throws Exception {
        return inflateCertificate(encodedsubCA1Cert);
    }

    public static X509Certificate getEndEntityCertificate1_1() throws Exception {
        return inflateCertificate(encodedEndEntityCertificate1_1);
    }

    public static PrivateKey getEndEntityCertificate1_1Key() throws Exception {
        return inflatePrivateKey(encodedEndEntityCertificate1_1PrivateKey, "RSA");
    }

    public static X509Certificate getEcCErt() throws Exception {
        return inflateCertificate(encodedEcEndEntityCertificate);
    }

    private static X509Certificate inflateCertificate(String encodedCertificate) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(encodedCertificate.getBytes())));
        return (X509Certificate) certificate;
    }

    public static PrivateKey getEcCertKey() throws Exception {
        return inflatePrivateKey(encodedEcEndEntityCertificatePrivateKey, "EC");
    }
    private static PrivateKey inflatePrivateKey(String encodedPrivateKey, String keyType) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encodedPrivateKey.getBytes()));
        KeyFactory kf = KeyFactory.getInstance(keyType);
        PrivateKey privKey = kf.generatePrivate(keySpec);
        return privKey;
    }

    // generated with: openssl req -x509 -new -nodes -key ca1.key -out ca1-cert.pem -subj='/CN=SampleCA1' -days 3650
    private static String encodedCA1Cert = "" +
            "MIIDCTCCAfGgAwIBAgIULiO+FD0TraF5K8ga7RQIZuYbE5EwDQYJKoZIhvcNAQEL" +
            "BQAwFDESMBAGA1UEAwwJU2FtcGxlQ0ExMB4XDTI2MDgwMTE5MDYxM1oXDTM2MDcy" +
            "OTE5MDYxM1owFDESMBAGA1UEAwwJU2FtcGxlQ0ExMIIBIjANBgkqhkiG9w0BAQEF" +
            "AAOCAQ8AMIIBCgKCAQEAplqR14W+Rt5qnv7WYQhsFb7eaYSzl4ClC9voC+pOe+bm" +
            "QqXo8uX6G8PDSEiM5VQxa6SGuCt17vcPnMaPuZim2+nBh5yV/Npglx/Eb4uhjgVw" +
            "qIY5ucsugvm4g4EkM8OoMBdbbd1a0nJOW6JYLwLjOc5UowrBt08e+GddPxWPKnlK" +
            "mxPK7eqxKb/mxkj8bcDV4q9YA036b0spg19/CI2neFG2UTPPg4HL141a4FRhU1CP" +
            "zWpWhaEmlbCr5dMyCSSz4LJfkmZWPx0yYDMpPuzDXozYROOttQc+iI2Gu4zSxGvM" +
            "1lqI4hjWyTVHcG40AV0pSusG/sBoAOFlCvs2E/6IRwIDAQABo1MwUTAdBgNVHQ4E" +
            "FgQUDn1PboL+0Nlu49EdjFBMQrZoVyIwHwYDVR0jBBgwFoAUDn1PboL+0Nlu49Ed" +
            "jFBMQrZoVyIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAd/W+" +
            "hrkrhdL/CzGiyc1roGLzJ8zENwO8iK8guLCJLL9PKQ7rZzKwYxZDuPVQIgofk65S" +
            "EQWVh9En+jZtE1GFJjxp2q1FCeutQcs+YWK6tKe5SPwNub69bX1Ic96TT0fS4Co0" +
            "/K445DIrW1hsAw+QNgSJJie8GLW/xOcygX+rDnB5Q2aQFbPdE8lSFtekC/l2Tv/D" +
            "DWcy7sfdUlHoFEbFmyw4PdzFyhCNYBLnPdiyybfKbCcMg6eTwDE/TKlIFyIdqc2c" +
            "+t+0pD3pChEbSynKSWZSR5BWmZEczIHruu8AHAsjcY2uMwEr+fmjbJF08s669bp2" +
            "+K0rLgHIF7cW6zdCPQ==";

    // generated with:
    // - openssl genrsa -out ca1.key 2048
    // - openssl pkcs8 -topk8 -nocrypt -in ca1.key -outform DER -out ca1-pkcs8.der
    private static String encodedCA1PrivateKey = "" +
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCmWpHXhb5G3mqe" +
            "/tZhCGwVvt5phLOXgKUL2+gL6k575uZCpejy5fobw8NISIzlVDFrpIa4K3Xu9w+c" +
            "xo+5mKbb6cGHnJX82mCXH8Rvi6GOBXCohjm5yy6C+biDgSQzw6gwF1tt3VrSck5b" +
            "olgvAuM5zlSjCsG3Tx74Z10/FY8qeUqbE8rt6rEpv+bGSPxtwNXir1gDTfpvSymD" +
            "X38Ijad4UbZRM8+DgcvXjVrgVGFTUI/NalaFoSaVsKvl0zIJJLPgsl+SZlY/HTJg" +
            "Myk+7MNejNhE4621Bz6IjYa7jNLEa8zWWojiGNbJNUdwbjQBXSlK6wb+wGgA4WUK" +
            "+zYT/ohHAgMBAAECggEAHtWPzc58997XDXR34RFyE0/HIvDVZwIR1ZJjvv2loYKp" +
            "cHYXKRqmksnk4vuLniBObsDWtcFcgTgrHSiS0FhyqTV5ST0lcfI6UBizzOcpQU1R" +
            "1fLXNVBrZRyLblicELo17QAPUtxiLrrAOmzrgn87BeZwOq5OPL9+IpXqKzzARiNb" +
            "bPh2mtTDVvPrDAJdxi8qLBI+4dRxss0qWUNm4irMM6bepWGhqHd8fjG4cysTy88e" +
            "0Fxt4LNnMp+9Bm8GC6NIF1IAWLmXoqV41O3a+OUsEzAoAGX5sBGm412xP08DJh11" +
            "3dTRNXQJQD2b5XfRyGNfNRJO3jehU65Ky2Y4TngUvQKBgQDjNoOg7Ji88tJlIsW4" +
            "oT2Jn/pUxVgTbGLVX3pTeDp5ogL+lpb959rmYjxl8bnjdvjd6su35fcbgP5MPHvd" +
            "/JK0wcoQwV2S+FbjxlYgKiKoCwD2jdWNZsfuS9nFl6q0tu6LC9fNzcJXbDOIh75d" +
            "u+okjk6XjSo/JC/d9FtnexqhVQKBgQC7biIaG+MWyv2F2uiKu+BCd3J+HTb6rdVe" +
            "gqEg849ZUzPqWsrdg07erdfx887qKfYAm9C9Y7D//BKjTmzzc6CTPUCjI/vjrFRT" +
            "wXqpqXyV6G5yjAhRg2EFzWWGN2cz1I4FoNp7uXMnfPq/BfGoQwBcniXZ/qsgqwzq" +
            "uT5ltNuzKwKBgQCU001OqAq3oNmc8zTNZZf4QHho9EZnmpP2LS7j45lxuGP7vEm0" +
            "kBy60Ne88qOO0YvbWAMONqwwMMLgzrFXyyuRCGpBpVaUgOPxGCWrtc2zglmkJW0e" +
            "zJbiiH5hRaHD8xq2qxA0trS4LKBoqnlPzllkjm3+KLHmX96WpIsGcgUUbQKBgBwK" +
            "nSWE2JPXaNi26KWg+CtZjZKaslgM2+hY6NxyNBcsII9GaCV9+LXOEonLbUCRaJGs" +
            "vi0nlhqmTu+J0zkVKof82QfPYWctqCwjvUNW7SHMdYHDu5bebgydLzxGW7VgbqMe" +
            "7rEmDLlytF0R+Zav94Tj0EvuExI/JR6U+mXjCh+jAoGAPTq7fPlTNaFJ8XPEKYX1" +
            "avL8k1DsWAQmLbebPy8xQ8/bvfAHzRuMqoBiAihPtCS+2AkOewT+APrDU5MboJNN" +
            "b+GJLKHomiUnvCYp+XIOeYtWvfNGS0oy38vCmsr9jaJcuHUhiYVGOCC0Ft5G5OG1" +
            "YxC60keoXkQgtubvr+LVXXw=";

    // generated with: openssl req -x509 -new -nodes -key ca2.key -out ca2-cert.pem -subj='/CN=SampleCA2' -days 3650
    private static String encodedCA2Cert = "" +
            "MIIDCTCCAfGgAwIBAgIUaMikI7PsbI02m9H8w301Z6OQdDEwDQYJKoZIhvcNAQEL" +
            "BQAwFDESMBAGA1UEAwwJU2FtcGxlQ0EyMB4XDTI2MDgwMTE5MDYxNFoXDTM2MDcy" +
            "OTE5MDYxNFowFDESMBAGA1UEAwwJU2FtcGxlQ0EyMIIBIjANBgkqhkiG9w0BAQEF" +
            "AAOCAQ8AMIIBCgKCAQEAvg2lsTMndeHj6JZBKJ3RFstBCyw2gwGPVoXUcKWX3Uie" +
            "/6zWb1w1HZdlpoj3MpE23Y0mPslBw2865KTe78ZUg6x11AHzEa5v6jVLLDnURD0Y" +
            "OuG6wBi59Xg24054buUlBpUqt9ZtLaq64PIzdrho2uiJEIIcV4a6Jv7p6hkhMWsd" +
            "0Lj82v9qdts4RpXSXXw7VsY1bRBxdFnZ2+t6/V7i9+WmsTqJMhLlWgJON5iL9w2u" +
            "g7lK9eudyTgtw3PzrVi7qeVRlhjG/9xH+DMkxUpQhdVTc1x01RuXDODujIrb3mZN" +
            "io1D+JjFKCo5qC6NsAugnpQWmFr+aig7e6DwbE+i1QIDAQABo1MwUTAdBgNVHQ4E" +
            "FgQU9kieckpRHxcSLEwuCZhjM4rQ/JUwHwYDVR0jBBgwFoAU9kieckpRHxcSLEwu" +
            "CZhjM4rQ/JUwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEApTVs" +
            "arhCLvpRW36f0Qa/lncoPxjfMkUoWLaO1mT6evPEEqM4Jn8ZX+lshjGpdkUxg1OM" +
            "8Wk8SPNQqwTDTCGipYd5hVaS6SB5XA6krhQJiUmLHvLrOuuJbpSN8seib+ZBekr4" +
            "69tWT/7W/D/3yv0+BKXjP8TzuvkUQDYDF8FbOjEFb0mMkGiz9XIbqLAjUzEOgyqy" +
            "40g5YnD34MpXsC7pNnhwLO5ypolbAgdj8KG0uKPYPIDjff1EGlapTfiSGRadQRJP" +
            "WV1NNw5PzrjCTTQ7GzhAnuGwkhQ6w4VhZsc5Wya0EGDuNI+NKdvFeJKbUQV/CLZB" +
            "V5SON+w/RhHx124hew==";

    // generated with:
    // - openssl genrsa -out ca2.key 2048
    // - openssl pkcs8 -topk8 -nocrypt -in ca2.key -outform DER -out ca2-pkcs8.der
    private static String encodedCA2PrivateKey = "" +
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC+DaWxMyd14ePo" +
            "lkEondEWy0ELLDaDAY9WhdRwpZfdSJ7/rNZvXDUdl2WmiPcykTbdjSY+yUHDbzrk" +
            "pN7vxlSDrHXUAfMRrm/qNUssOdREPRg64brAGLn1eDbjTnhu5SUGlSq31m0tqrrg" +
            "8jN2uGja6IkQghxXhrom/unqGSExax3QuPza/2p22zhGldJdfDtWxjVtEHF0Wdnb" +
            "63r9XuL35aaxOokyEuVaAk43mIv3Da6DuUr1653JOC3Dc/OtWLup5VGWGMb/3Ef4" +
            "MyTFSlCF1VNzXHTVG5cM4O6MitveZk2KjUP4mMUoKjmoLo2wC6CelBaYWv5qKDt7" +
            "oPBsT6LVAgMBAAECggEACPpPj3tlYifwBaXXATwG3pI7UE0/7Ct0pQEKH0hVqdYb" +
            "O33KAzVia/N7Xlg3gMiQnftXAtD46pDBTsyfNfy5ZtJZhMP5aPMp/1dFP3S7rn29" +
            "ViC69Lj/5dTbMOmQZMEUOrqgRTibn5qvHJIZNMLZO/tCm3ut95BNdsSePtj98xEL" +
            "QehngLVa71CYUxvUdGatqOkIsQFEDHhPoyVUegNEnrqTQEcrf4DIKW7zq26A/zaV" +
            "6wRnVsPgSHQvcat8S4+7k0rtz+3X4Ch4Q3EmAJxc3YdnumUM3yBxjHzTkUBec9f7" +
            "Io402Q/lpm2gmFM5joAiwWtG46BhFksIbQYBCJUS8QKBgQDueQ4l9iBXQMvryhdS" +
            "jVeVbZc89MZY9Xfw5M8136bHdxc3BQoufh2qwY8lkL1XNij40SNp0ujcSqdvxXc9" +
            "JPRlJnOYSagVEnLUUPqvP7/R6aiayEH8TyJOYUlSFYf+qUz3qOykR2TOSKpQwCnR" +
            "UqkvSWFmKgZGWIs+fFkh78ISJQKBgQDMBY/n7nigCohfRxEfUFdIgf9ivdg7yQwq" +
            "KaZjMhczJAbvzoVFo7s9h6AKDZ+FbxvlN0hY96VsGceYe6A9/3xgncGabvJlYUEt" +
            "5u7o40D741yqS++LW7JR92KRg6XGI75Qkt1ZEGGSXi42hB4Qz6xBsrPjvI4wOcqT" +
            "DoBiKGn28QKBgC4KhzXDEDloVDag3OHeUhOShgmJxKW2NsL2mh7voDaQgpXnzjBt" +
            "vvKRzj5VdIja9wwa7LhotPabHzqQKFZQxTKmOtkjF2WCG1Nskwm0yCcR8rB3i23Y" +
            "JWp2k/5aE9iR/T8viQiqlAbTtrZCc5BrYii0BS8BXBbGz5Nv1JGdxZ1VAoGAKQld" +
            "XqtKu/YiY/epbAD+7Wioc7X3zl6sAbcK7pzeqbyvYIDLsawzNzcWa689zNsCY2Jx" +
            "POPi9BFjYjpLiuzemZhhnqx+OQIM2CzBFTrQkVm0A9TuQ7uX7ICz5Mz0BRyfZRmF" +
            "SCrRVV14MiL04TDEVxqYsE/20aBuLJIYJKY4WiECgYEA6paoKS4JCcuHuhVProBt" +
            "iyydIAY2xVQ+dI7c5Bvb10aqBYcaOw60IJLzss3FwNbIkXKD0BqpLvS1gxjFbWst" +
            "Q6XOkLhCkLNBBztvtxgt4Qr7XYfMskE7Se58s6HnaNMKmBsOG8/MsymQ4sGoNMsh" +
            "e8KEYZymadEhxdQwx43AP58=";

    // generated with:
    // - openssl req -key ee1.key -new -out ee1-cert.csr -subj='/CN=endentity1'
    // - openssl x509 -req -in ee1-cert.csr -CAkey ca1.key -CA ca1-cert.pem -out ee1-cert.pem -days 3650 -CAcreateserial
    private static String encodedEndEntityCertificate1 = "" +
            "MIIC+TCCAeGgAwIBAgIUK5saxd9pPEwqail/dbd8OcsLj+swDQYJKoZIhvcNAQEL" +
            "BQAwFDESMBAGA1UEAwwJU2FtcGxlQ0ExMB4XDTI2MDgwMTE5MDYxNFoXDTM2MDcy" +
            "OTE5MDYxNFowFTETMBEGA1UEAwwKZW5kZW50aXR5MTCCASIwDQYJKoZIhvcNAQEB" +
            "BQADggEPADCCAQoCggEBAJyYenlwcn8zaj7F+eMv2heOoKdq1gcqZEHjJOqFTH61" +
            "lhznbX8IjHblQgjq4u+megeFJML6H/Hfa9yHuHyrgsyLjNt34FyIP5tsHT1a4dfx" +
            "M7f0dZW1/Wsrg7qWwZAupinShl8Uovl9jcCtSdpPOgk5vBw/hqMGu6SAXLfvc0ba" +
            "lsU59eJarc/WeacFOlLFaSLI65UStbtNBtOUq6iDMg5/r3HCY81vcKZTyFebRRZM" +
            "AntQEqm1ufRPBjQJG3DfNRBQt8qlLL2H/dddKBximpP+qisvNc6KihmJn0Kjacbd" +
            "0wucKMuS2kyl08DpROv5G4KXjo4GlPd1BpO6J3sM5P8CAwEAAaNCMEAwHQYDVR0O" +
            "BBYEFMMd8Lralv0OVdcDdT6ZLXpnUuvPMB8GA1UdIwQYMBaAFA59T26C/tDZbuPR" +
            "HYxQTEK2aFciMA0GCSqGSIb3DQEBCwUAA4IBAQCMNWThBPM7PCDLnQkw9iFSnRIO" +
            "kLVmqHoIfaMH3p7+LZh8Qo+indbY4sUXSMWxa5vLkhYMlVbeJ7L+Z0mEJe1zyxf3" +
            "IMNzn5r37qitkSBI7g4Nq9JglWNY4UdjQWnedfDK5wfjIIaVjl3gk7TVfC+kh1Tm" +
            "xUFzdhaccLIqfaqD2NEeWsZaVXXHR27d2w/QkquIdd3R5J8DXrKDke/3kQ6HrjRH" +
            "iyXxR4RclAiPyZFvbd2EH1Of+8P2r35aclwL0QrYfVSdKZB4rsNIRIQN004bX5+s" +
            "cNE1lvIJOu6KhjmBm1D3dHNlckxyTcOkEtRhrTdeGITN4QkgyhhXuM8jzQPz";

    // generated with:
    // - openssl genrsa -out ee1.key 2048
    // - openssl pkcs8 -topk8 -nocrypt -in ee1.key -outform DER -out ee1-pkcs8.der
    private static String encodedEndEntityCertificate1PrivateKey = "" +
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCcmHp5cHJ/M2o+" +
            "xfnjL9oXjqCnatYHKmRB4yTqhUx+tZYc521/CIx25UII6uLvpnoHhSTC+h/x32vc" +
            "h7h8q4LMi4zbd+BciD+bbB09WuHX8TO39HWVtf1rK4O6lsGQLqYp0oZfFKL5fY3A" +
            "rUnaTzoJObwcP4ajBrukgFy373NG2pbFOfXiWq3P1nmnBTpSxWkiyOuVErW7TQbT" +
            "lKuogzIOf69xwmPNb3CmU8hXm0UWTAJ7UBKptbn0TwY0CRtw3zUQULfKpSy9h/3X" +
            "XSgcYpqT/qorLzXOiooZiZ9Co2nG3dMLnCjLktpMpdPA6UTr+RuCl46OBpT3dQaT" +
            "uid7DOT/AgMBAAECggEAAYBIr1ktI36N1VQPbvB5VjDvSDzLjm9prAGOQgmR2cQs" +
            "nuYoG4zKHv2m2FKTyY+NNUvcmG3iJyAaAKuRn2Xb9L2KpIK1IX8tKxIqUjR5+edC" +
            "Zbx+jtTCeCLpzakXONdze4yJAfwrMjyZLuG6X26Er11+PZiemxcoR1KQ6ZU9MDEO" +
            "/sSPUuI6Lq1MHTkDeQlbLe3n+K97DsPCKbDNLhpU0vH8L7lcPJoPkwoBvkfSVUME" +
            "G/8lL9D/aonhuNjm2428p3X7s8MXbGj/C2WHtN1CB1kpa/t0U9Vsjrb7T4FwL9V7" +
            "HoFxz3lKSQihfSxDMNTsDJT/yMbc9zKCmaXiZQ4xWQKBgQDZXcSS2bCECD4oTIt4" +
            "BP5pr4PcqsPr/XqdM/E7fC3oKwQNRkbFUbaAko3g1sZ7DzT1uj1oLW5FGUrDwYAx" +
            "NlI1+69546kUns2IjQNzijR2WdulXM4Pk1J6ZpksB4XTAenMrXCBVpa0CFIrywN6" +
            "kAL82SCnK9y7nIG95SHwjSM8hQKBgQC4baB7LWWNT1B28cKq7k4ynY0xl99dZ6o5" +
            "w4syrj2W+vHQzinarrHQMHfhLgFVAv+Lyv/wxy7JZUlNRy4qBQVXfSCYcDTBFpBt" +
            "KyWRHXaoAgtiQGcarDowrkS6cBEU+0D/Yhwab00+rba2/g4D9yuk3eLVm5NelL70" +
            "3KnQO/GEswKBgFFE3LUnDPcgedTpYY/bFh//jmaXti7qk8ho3j2mXSebxaUM7HLj" +
            "7T8/DCrPQmBKPDvPiRwFOGA/Z5OvKjW8IJqsYlxJQTNDeIcgafTt7FV/nT7DZwut" +
            "wj2fVI+AtIlDAt4Szqic7jWbktVqzv8pDuTobWvzW1EN3/hWzgy5SD5dAoGAG4cR" +
            "axFNlRf/lKFlQwoq1dc6WeqnRlPQzqpnPntPaheuvFHpYWCt3bs+SXgKbtvxtLXq" +
            "GdBBJYJevJAhTdhOAc8FbHtjBGcPy5ujEdPqAA2+ET43pX2LefSpAYL0qcMO4o+M" +
            "Tk3Ko85d9VZaVTExbHxJ/UQpbPaawgWluxUXaY0CgYEAxzCNWh/0GdLmnzCUq+R1" +
            "O9laIiXX/OhJGAdLhNVJBIo8vLTpRo/j8FWTqzbE9uZxkRkwA+RbQTS1kFQCeZ/Q" +
            "TUektmAkgFHvzgThhk8n0F17uidqky63U2jY9wC/Jqyqg27b91Y3GF1ikxZ+qDHq" +
            "2IixS5dfBPGq5Z8Rasvc4Hw=";

    // generated with:
    // - openssl req -key ee2.key -new -out ee2-cert.csr -subj='/C=NL/O=Kwik/OU=Kwik Dev/CN=endentity2'
    // - openssl x509 -req -in ee2-cert.csr -CAkey ca2.key -CA ca2-cert.pem -out ee2-cert.pem -days 3650 -CAcreateserial
    private static String encodedEndEntityCertificate2 = "" +
            "MIIDKDCCAhCgAwIBAgIUApSbt2dB3bCn76N5R6zV3aHg5J4wDQYJKoZIhvcNAQEL" +
            "BQAwFDESMBAGA1UEAwwJU2FtcGxlQ0EyMB4XDTI2MDgwMTE5MDYxNFoXDTM2MDcy" +
            "OTE5MDYxNFowRDELMAkGA1UEBhMCTkwxDTALBgNVBAoMBEt3aWsxETAPBgNVBAsM" +
            "CEt3aWsgRGV2MRMwEQYDVQQDDAplbmRlbnRpdHkyMIIBIjANBgkqhkiG9w0BAQEF" +
            "AAOCAQ8AMIIBCgKCAQEAvh/9Yel+veLhzMNc7CHwgjZXBvbPoUsgAkgGwPCB/bBr" +
            "B9j84Xr8kiD0skCI9/lXCfd3umS9tXX7/0uCd7MjuZG7e8vHed+Fr00F49xHslvO" +
            "yMXsquArtNKBqTVAoFg5LbJnkOnFA4Yq+oX1TEUR9rGSsm1lHf+l0IA7DBM8RJ1v" +
            "rHPdmDG4qLWCCrafp1fMJqyofP+1v3LXsPF4bAz13H2OmDWNwsCNKUyFHb4ral5t" +
            "hizqyUn9idCmujFCnu+OdD3JpiSbVgWc9QzCv2kOLyHbYBPL6P/6nu3SlD8TtksQ" +
            "x0UCzZ7yjBQP8pAMxzYH7IvxMD1Xq3/gGF/ZrxfYSwIDAQABo0IwQDAdBgNVHQ4E" +
            "FgQUUlTIw5fR8tPxKrPO/fvRX/H7rawwHwYDVR0jBBgwFoAU9kieckpRHxcSLEwu" +
            "CZhjM4rQ/JUwDQYJKoZIhvcNAQELBQADggEBAIAd2a3pXMuBc/3Lp5JZQ4TjDxKl" +
            "ndjKfZ55ZREf+pxWD3xvjO1YppIEqr9ZahFpYaYMnn1i5xis1rcRyc6jJKSZxQqu" +
            "ORYWHtGknB/ddm9knhsKGUicqziSpOPkviqUetD0ub4jJD7E2/nUSaB9UJVbNUBx" +
            "Ftofuf6MYDkHXeu7X4OCx+iQqZcyLAxrw1jQbdcazwrfdV3/QRho/CE+ur9oD6nr" +
            "qkgWeko5ybfHgba7Zdxt0B2U+PKemOh5dtl0gbNrn9ZKHh5yuTbdzpbGijU1BIop" +
            "BYy/MVCVxNxJmyvkkMkkyoQtIwei/Lb81BoDFyUOOdLIbjLE1uHYjzVhyUc=";

    // generated with:
    // - openssl genrsa -out ee2.key 2048
    // - openssl pkcs8 -topk8 -nocrypt -in ee2.key -outform DER -out ee2-pkcs8.der
    private static String encodedEndEntityCertificate2PrivateKey = "" +
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC+H/1h6X694uHM" +
            "w1zsIfCCNlcG9s+hSyACSAbA8IH9sGsH2PzhevySIPSyQIj3+VcJ93e6ZL21dfv/" +
            "S4J3syO5kbt7y8d534WvTQXj3EeyW87Ixeyq4Cu00oGpNUCgWDktsmeQ6cUDhir6" +
            "hfVMRRH2sZKybWUd/6XQgDsMEzxEnW+sc92YMbiotYIKtp+nV8wmrKh8/7W/ctew" +
            "8XhsDPXcfY6YNY3CwI0pTIUdvitqXm2GLOrJSf2J0Ka6MUKe7450PcmmJJtWBZz1" +
            "DMK/aQ4vIdtgE8vo//qe7dKUPxO2SxDHRQLNnvKMFA/ykAzHNgfsi/EwPVerf+AY" +
            "X9mvF9hLAgMBAAECggEAHHZHhWfiHGUhrni0qXjvO18NKjK6pIfNk+nacPnQS/0k" +
            "GLmoKc0ykGG0oBa/Kng+SnSsjM/WAptWDULtliPQPlCNw5ufEiSfK74ZGqJ4bUAH" +
            "NdFDe9UxVdGJrZ4WParXbHrfvDby0nM8beKt9SwF42tz7Zgo4hPKa+s2a7lZdV/m" +
            "AWNJWv/zJILYX0Bh+huVrjBZQn/qzseAz6OSg29K7GdBgqT3Ts7qn9DBXEc9OGDK" +
            "e3//ilrFpsRv5cH8ER+fHHqpOuMlmMIs9r5bQzBsHJaIbATzjwl+8/iXCV+eWSaf" +
            "7i3aZcZSpLEBuxgU4E2C/1og7oTamm2BQ1dJhhoDGQKBgQDtyyl9T9F/QvRJonVQ" +
            "cTR4LQSCFz9kuCnmbaGLb/FPCxGhnViqtVk7yHvnXG6P/kPV9sDwjrt6zZLi466l" +
            "t/lLLLpGk8QDRJ30fqwEafDzysRaQxbQJV/4k2Q3YmFus0wLYFRghTz0U2u8FWSl" +
            "DZxJ8xdRiAZGYCIDUNyqCU90jQKBgQDMroFweqZBKUVpTaWATlZ55P2D3fvhEhRS" +
            "vkd+YC4rHkmQMfw53sTtyZ8I3d4JY4uG4Q4D0mJ3HBrwem42bnjM/xXFkaZhbm7X" +
            "RpEeu93v1XZYQ1XeJhK2ul+l8jUduYS/Fg6MN7dv71hJ8idB0+RwYH6BbJ+5WmS7" +
            "pSImMRSGNwKBgQDqFACOg4EFlmIlDhAPlLCC0EXMzZewzP0qAKdyPEq9dXbwsZQz" +
            "zvq9N9iIYlvP0Qrz18gLxWVWOIEsadZk+Vokny3rBdCBKw2WPQ+V9LelNOfetoYB" +
            "dZkod+bCAk1JDKSB2lyU+vOKy4eVCTYep+w+e1ZsAsuygTVaMEJX+3xEjQKBgFXH" +
            "xMOpA0hHzalGO1g8fI11ZLIBNHCtLQtIZ5oVIQQ9G0NtT3HJZOrrFtWWdlmk+HK8" +
            "my0K3O1iQAAMr2fsgIAZX7x/QCWRLK7YCjXBMlAzO/fdsHz7o9gk37UifxRIDdQv" +
            "oEUvjJdCzdOfwsgZz6ExL5N6PK5nrdPebyNmal2dAoGBAMMW+0nozHyAMCokLCHK" +
            "CZs79FXvcI6kxS2gm8Xd6Cj4TYrpoqAxvAaI7Pu4KisAnEz845cN/CLoqvF6xXX0" +
            "X+8ewYUo11CKHg3n8HZoEibC1ddeEiZJfOzhKfptRjmDS1xuvScnfrLg1EutQ57x" +
            "omrWVczJ6h8e77Vul8AM31pH";

    // generated with:
    // - openssl genrsa -out subca1.key 2048
    // - openssl pkcs8 -topk8 -nocrypt -in subca1.key -outform DER -out subca1-pkcs8.der
    private static String encodedSubCa1PrivateKey = "" +
            "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDmKXJnRUUfuOvc" +
            "GnGOOvCR94UEe+hou74GW8QRm1t8mIIopil/lezUen4bf98Iqnc8s4wQqpMqfLLK" +
            "G60a6LSELxxFTS0GtHGVFZYP1jdNC8bu8Q2xDE77UvtIHuybIahUnzhRkDEG1E5P" +
            "dgmq79+ShqUldF7LTuML4OXMDt5xiz9cdrgHZ+BfTiwTsX6cS865hYh0CNbN77g+" +
            "nu0o8gOZbE8EyG/GFIVtUSGDJPJ1mOhUW/l/gCm84K23GQngEi50tzOtaeBpR1v7" +
            "VD0jAxEYf9rupCTYhV116Xazl0U1w+jgFrrqktFnP8datvOhyhmfQuv2o8vr6mc+" +
            "62ZSj6jhAgMBAAECggEAYlfSUKrp6rCGYvEPlTC86vmiZfSVrO6PNsNOByHlGNtH" +
            "PhwlfiTu4SkHqjNcdqTztsWW8uYXZJ+Me0wRDn7g5twETd44f3VpVMS47kJfNbXz" +
            "BdSMv5odQ0jFIp9IBM8AUEwJ8dvU/vCHF2+9mMLOuhp7BQJwoJkv7TrmpWazCDsi" +
            "VNTj6sBGtEhjWWkq5SwHqBSRA8OdUEinpjZtwpN3FiUEpwuSn0RivN+CNfH4dhls" +
            "LJXuGTauRZ+t4sEnwpEjKi5BNo28PPRzIchG2F5j4JWiIe+r7w9q8Bl9I+1E5hv0" +
            "hT1hq/sm2B4jrbEp22emw/isUXbkjbW9dTkONA6z8wKBgQD4hf5hoyeUo3k3F+VJ" +
            "Nlpun5cdevqG3g5CxmVhTBrVzSHSVflEPVXSoFcrf+YmXpvVtrXjvCRu4MejiC7Y" +
            "Czib3VRBCpNT3qLAUKnKTPCcuGdWE8YyX0qQGnxFDgEh7hh6vA6Ee4AMQXdxUM/y" +
            "16H+825mq+h7ZG5gPEbESvF+QwKBgQDtFgqzA014TPX+vprz+q8/fZmynIhfGseu" +
            "+WoyKlzs66bbAoVXi5/k8Ba3bTtdgKFnKU031rkiYHrFzlQrR3XET9+mmVJaN6w1" +
            "eY0QnOCYoghbwZrQU27rxJoQwSjiBBtStCXqen5LusxIYcueHnboMmbMwQXw3bD1" +
            "UPVREkYUCwKBgQDPs4yqJSVLQGRp+vqReW+SzKYK6WC/no3kmNLZwjUbQlll5Jxy" +
            "v6AebAruO/IpVyB+ODlDn1YDpLC0p3ge7yHcgdmMkj4W9hanC8MbY7okAKm8csJO" +
            "Dv3N+ZSqUc34gXjL+qdXaa/WjlA40AU7O6QT43b9L+cYWRM2MqoiG1BA6QKBgQCG" +
            "TKoa5ZAIyW+/sjEMa8DB8mASMWF+nijnERn6+MxS2NpXzYHDKbCVevsjRJkQSkEj" +
            "st2u988/je9+BXbgXUZ0wdorAUcJG+hNEmG6O2NukrqxX2ZXBCwdGe07+G80OKdR" +
            "ngKsZF8Ofu4hQmSZWSB6P7LD4cN/wdTv4cBVAEj6KQKBgQCHDcPtThny2F2VIM2c" +
            "XyqNY6MzgP20ep638MX7C5VozU2pqh5b9W5dXILu/l9/OLeqikPGmkyqIfjRTB1S" +
            "bQo1yYLf9SfYqC1slZqv8Y3vCSUn/mTDDtCflUTbLt2dpgBTLlAkjne1COQHj6Rg" +
            "Bi9puL0l1kQ+T1d8x4q5dV6TPg==";

    // generated with:
    // - openssl req -key subca1.key -new -out subca1-cert.csr -subj='/CN=SubCA'
    // - openssl x509 -req -in subca1-cert.csr -CAkey ca1.key -CA ca1-cert.pem -out subca1-cert.pem -days 3650 -CAcreateserial
    private static String encodedsubCA1Cert = "" +
            "MIIC9DCCAdygAwIBAgIUK5saxd9pPEwqail/dbd8OcsLj+wwDQYJKoZIhvcNAQEL" +
            "BQAwFDESMBAGA1UEAwwJU2FtcGxlQ0ExMB4XDTI2MDgwMTE5MDYxNFoXDTM2MDcy" +
            "OTE5MDYxNFowEDEOMAwGA1UEAwwFU3ViQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB" +
            "DwAwggEKAoIBAQDmKXJnRUUfuOvcGnGOOvCR94UEe+hou74GW8QRm1t8mIIopil/" +
            "lezUen4bf98Iqnc8s4wQqpMqfLLKG60a6LSELxxFTS0GtHGVFZYP1jdNC8bu8Q2x" +
            "DE77UvtIHuybIahUnzhRkDEG1E5Pdgmq79+ShqUldF7LTuML4OXMDt5xiz9cdrgH" +
            "Z+BfTiwTsX6cS865hYh0CNbN77g+nu0o8gOZbE8EyG/GFIVtUSGDJPJ1mOhUW/l/" +
            "gCm84K23GQngEi50tzOtaeBpR1v7VD0jAxEYf9rupCTYhV116Xazl0U1w+jgFrrq" +
            "ktFnP8datvOhyhmfQuv2o8vr6mc+62ZSj6jhAgMBAAGjQjBAMB0GA1UdDgQWBBQL" +
            "3sBKZlro6hTGP0JinzgT5DPx+DAfBgNVHSMEGDAWgBQOfU9ugv7Q2W7j0R2MUExC" +
            "tmhXIjANBgkqhkiG9w0BAQsFAAOCAQEANXy8nDEo3GO+PRQ6CzOBWPXdeTHfxOq7" +
            "ruPBqe+wP5ZwLtLU0rWg5fTbgMNNMOJrZo2gHsgcHjKm1rRudHrzqfOvY/pjjwmF" +
            "RyaRPWyaHiOfO2V6mvEOkD66h+TfTRu0GU1ua6k1Rm94/NZ3J5s+53eDx2ZJ7szX" +
            "rKMqy3bw6AmOhtKcAgJrRLstYpKkpa6CBxBHSLfTyfy1kohTiURJXbgtInmhjSj1" +
            "pu7WsSKlaqdK10QhbFQDKuF+xhzxY6YXrL/dt4+hH2w2fAXT/biQP5WZ/I10dxHk" +
            "3Tx8HxE/dJhHGc3gnOdY8HXP/LZIJ+pwbaqv79HB9ymlxUXPHRiBMg==";

    // generated with:
    // - openssl genrsa -out ee1_1.key 2048
    // - openssl pkcs8 -topk8 -nocrypt -in ee1_1.key -outform DER -out ee1_1-pkcs8.der
    private static String encodedEndEntityCertificate1_1PrivateKey = "" +
            "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCuumg0qOUkTZwF" +
            "ZFyNraTl5UGzI7fN40rftNMO+lhPOQA+fzJHgX3BXJqrJDic8ESew9jLSW1JnBJg" +
            "dhvG6H7UTxXMu8ej/PI7eonVwGuTUKDMOu+31yCxn7XDVchgH67S6nA9nqofc41Q" +
            "2ILa3X2NT7xOGQ8jcJOz/1DFeayS1ImQrftwqUsZO0TpAq1VDviedjNcOICOnjma" +
            "2V7QVBONQSYF8Cgl4pSsl6i2h75nxiUm9/rRW52SXIq8Pxht1vEuRNhxNbeW4PJk" +
            "vlacE6Z42OE1A7F+I6lvwQN0r5nyejU5JU0ouFxWCd2geMENSdW9NHIRe0Nf3pFH" +
            "CVav4E5DAgMBAAECggEATpP0QyJlknL4pJAi83BRBTaZ2ldI1OXQCVUHyeeaCV7I" +
            "FlMbqH66sFfWEvtCHooLQh8vgxStenoe5ZSYH1b1msNKOX2FZeFeipMsI53agzCy" +
            "b8Zdgh7UTC1YD9WnPFtjQuU9vuh495X+yonkJ0uOqBtgwvqQDU8Wjc9XYse6bXk6" +
            "d9E1wE5mXcYVA+1RwgX0NBf4a/nVbWPemEV4vG8+boqVX3/gNoo4u8JYdJ06l6dl" +
            "tIc2nHR6/wX23XHzjSpZK5IewQPAJ+mNNTkVSJOTux9Ka/erX89iksIzxKi3khOV" +
            "RCWbt78Ws2wtSAmLLwPtkpBEmSFSupN3n89x76NWSQKBgQDqm9yne1eeM95+NAaz" +
            "5WyzLXMxt4mwdxNpenCjYbV5mroB2stv+6vYnU8puk0IXUuaBBwf2E2Q2G/UOnEu" +
            "aK330RULpG9YCpN7fX5PXtgmUZze6PFD246vkwxwbQCu6TQI2VgPL/ObPE136j1L" +
            "ufak2Uli5Z6ss5ub3JUZjgk+nQKBgQC+qNYKGyvDoli/bZeB0cCin6CmvKmW0Kmf" +
            "P+4CP8s/hSnUSI97APXq/Wgpu705T+w0S4bn6Ll9B+GPqPq7xnu9P96F539AYJJR" +
            "EcYZhG6dUru40hy8SCnkiXYk4pcXNLYHD9ccRqgoCGrSXuxGjAaRQZsan+XDGivj" +
            "Gn/lwoS6XwKBgG3Luc2L9OpuHe90S7q/YUrNt36KBd9XKvePPM3JuZOKrQiXK+Rh" +
            "pQAARv8hWFHUz7/psnvY0Bw8nsF1BGkSxnAXIsFLGGzcrj758TYWDhSI12CfJeJ7" +
            "C2Dx8b1f1hUFwLtvdD3PVDPPWfYH4t3gzyRBKI4nJkZu3CFqb0EBbyQlAoGAM7d2" +
            "f71JDMMP0bU3gKZV24bzO+c3FUq6iBD+TaviRPOpGgUorlPfYQOl6pQbSt2ME89c" +
            "47E0B19I5wAOKzs2u2oEwUu/L8ZCSi1JEAjlPFWByCtuUgA9JNnIq06vb0MEETxR" +
            "vEDKQjmuSCwpaSV4bpReL0WqPFbwCqVYhglSmX8CgYBj9/sVVgZrbyHMg3VcXBFf" +
            "j7wjI2JhSY5FcxlCUdt9EycSYduGsKcnA9M9j8ZUgJX4NNN9fZWHjh8DY+sizrE9" +
            "1XRGLcy/mdh9bb6szx70UAPXbGcp+mFoIdsE5X741B+uZvrLY31IyEYiBU6i5xIF" +
            "Ns/jQG2Fn+Cw1WkaHWBdow==";

    // generated with:
    // - openssl req -key ee1_1.key -new -out ee1_1-cert.csr -subj='/C=NL/O=Kwik/OU=Kwik Dev/CN=endentity1_1'
    // - openssl x509 -req -in ee1_1-cert.csr -CAkey subca1.key -CA subca1-cert.pem -out ee1_1-cert.pem -days 3650 -CAcreateserial
    private static String encodedEndEntityCertificate1_1 = "" +
            "MIIDJjCCAg6gAwIBAgIUZVXUZ6aSgDktJ+JSlw4pMN8KnLIwDQYJKoZIhvcNAQEL" +
            "BQAwEDEOMAwGA1UEAwwFU3ViQ0EwHhcNMjYwODAxMTkwNjE0WhcNMzYwNzI5MTkw" +
            "NjE0WjBGMQswCQYDVQQGEwJOTDENMAsGA1UECgwES3dpazERMA8GA1UECwwIS3dp" +
            "ayBEZXYxFTATBgNVBAMMDGVuZGVudGl0eTFfMTCCASIwDQYJKoZIhvcNAQEBBQAD" +
            "ggEPADCCAQoCggEBAK66aDSo5SRNnAVkXI2tpOXlQbMjt83jSt+00w76WE85AD5/" +
            "MkeBfcFcmqskOJzwRJ7D2MtJbUmcEmB2G8boftRPFcy7x6P88jt6idXAa5NQoMw6" +
            "77fXILGftcNVyGAfrtLqcD2eqh9zjVDYgtrdfY1PvE4ZDyNwk7P/UMV5rJLUiZCt" +
            "+3CpSxk7ROkCrVUO+J52M1w4gI6eOZrZXtBUE41BJgXwKCXilKyXqLaHvmfGJSb3" +
            "+tFbnZJcirw/GG3W8S5E2HE1t5bg8mS+VpwTpnjY4TUDsX4jqW/BA3SvmfJ6NTkl" +
            "TSi4XFYJ3aB4wQ1J1b00chF7Q1/ekUcJVq/gTkMCAwEAAaNCMEAwHQYDVR0OBBYE" +
            "FDy1mTgJ3hnR6yxTpbjeFARgKtxAMB8GA1UdIwQYMBaAFAvewEpmWujqFMY/QmKf" +
            "OBPkM/H4MA0GCSqGSIb3DQEBCwUAA4IBAQBGiXNwdHn1x9leSxSpHn4USR3nWarG" +
            "gmIke1Dfa/YK5d23xknV+Q4SmsxTSfu2SxGkbT5IKOYf3wvDNcSHFUoJwOgTde4H" +
            "LsdVX+PhWadMTJIed0A8iksk8qY6FIsVcRz+/lKQFvsz9VZzJFZVZ+VJH9oofEji" +
            "bVLKgseomBxI3I7ZGABUVbafUQ+lvkNywPY5ioKMIwRN7nN7OJClb7nh1SM2hrHU" +
            "XRIvr+UUqdAkI8h8cnicfK5S1v7rovB9ZWBfK1j47Jeygcv52gKFeVs1pZrDHQaF" +
            "bAo1eoqMzcjbiyCc05XRAJQOAUsn7q1tr2R7xY4aUqhuYgGnDPBNDymR";

    // generated with: openssl req -new -key ec_key.pem -x509 -nodes -days 3650 -out ec1_cert.pem -subj="/CN=SampleECRoot"
    private static String encodedEcEndEntityCertificate = "" +
            "MIIBgzCCASmgAwIBAgIUNzmFH62kWOW8B6eWZSY5j2gyHwkwCgYIKoZIzj0EAwIw" +
            "FzEVMBMGA1UEAwwMU2FtcGxlRUNSb290MB4XDTI0MDUyMTE5NDUyNFoXDTM0MDUx" +
            "OTE5NDUyNFowFzEVMBMGA1UEAwwMU2FtcGxlRUNSb290MFkwEwYHKoZIzj0CAQYI" +
            "KoZIzj0DAQcDQgAEZIPsPYIIdFL8mbd5qPQuIwm7dVa/epFCY4vTnhS2tIw5RKaa" +
            "t1urxRvxMgi1/ColM8F/RFSFErR6A2ANkicNSaNTMFEwHQYDVR0OBBYEFB1vMRJd" +
            "cxjPwYJ9IXziKdyn4FkUMB8GA1UdIwQYMBaAFB1vMRJdcxjPwYJ9IXziKdyn4FkU" +
            "MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAJ01ZZtO6KPhT2Ap" +
            "ppgU3YodziRMezdkcXSawqBnwwVJAiBHY/ZSa3f9R95Jxc8MToS12QggtJaDSFCy" +
            "sV6kzP/1ZA==";

    // generated:
    // - openssl ecparam -out ec_key.pem -name secp256r1 -genkey
    // - openssl pkcs8 -in ec_key.pem -inform PEM -topk8 -nocrypt -out ec_key-pkcs8.der -outform DER
    // - base64 -d -i ec_key-pkcs8.der -o encoded_ec.key
    private static String encodedEcEndEntityCertificatePrivateKey =
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/7THqb775dzQvdOy" +
            "43UPGlTbog99/XZb9vTd6kgAZDihRANCAARkg+w9ggh0UvyZt3mo9C4jCbt1Vr96" +
            "kUJji9OeFLa0jDlEppq3W6vFG/EyCLX8KiUzwX9EVIUStHoDYA2SJw1J";

}
