/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package net.luminis.quic;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 *
 * @author illiapolianskyi
 */
public class CertificatePair {
    protected List<X509Certificate> certificates;
    protected PrivateKey privateKey;

    public CertificatePair(
        List<X509Certificate> certificates,
        PrivateKey privateKey
    ) {
        this.certificates = certificates;
        this.privateKey = privateKey;
    }
    /**
     * @return the certificate
     */
    public List<X509Certificate> getCertificates() {
        return certificates;
    }

    /**
     * @param certificate the certificate to set
     */
    public void setCertificate(List<X509Certificate> certificates) {
        this.certificates = certificates;
    }

    /**
     * @return the privateKey
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * @param privateKey the privateKey to set
     */
    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }
}
