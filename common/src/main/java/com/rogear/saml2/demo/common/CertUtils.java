package com.rogear.saml2.demo.common;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;

/**
 * @author Rogear2008
 * @since 4/18/24
 */
public abstract class CertUtils {

    private static final Logger log = LoggerFactory.getLogger(CertUtils.class);

    /**
     * ????
     */
    public static void generateCert(String privateKeyPath, String publicKeyPath, String certPath) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();

            // ??
            PrivateKey privateKey = keyPair.getPrivate();
            byte[] privateKeyEncoded = privateKey.getEncoded();
            FileOutputStream privateFileOutputStream = new FileOutputStream(privateKeyPath);
            privateFileOutputStream.write(new PKCS8EncodedKeySpec(privateKeyEncoded).getEncoded());
            privateFileOutputStream.close();

            // ??
            PublicKey publicKey = keyPair.getPublic();
            FileOutputStream fileOutputStream = new FileOutputStream(publicKeyPath);
            fileOutputStream.write(new X509EncodedKeySpec(publicKey.getEncoded()).getEncoded());
            fileOutputStream.close();

            X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
            x500NameBuilder.addRDN(BCStyle.C, "YourCountry");
            x500NameBuilder.addRDN(BCStyle.OU, "YourOrgUnit");
            x500NameBuilder.addRDN(BCStyle.O, "YourOrg");
            x500NameBuilder.addRDN(BCStyle.ST, "YourState");
            x500NameBuilder.addRDN(BCStyle.L, "YourCity");
            x500NameBuilder.addRDN(BCStyle.CN, "YourName");
            X500Name issuerDN = x500NameBuilder.build();

            long notBefore = LocalDate.now().minusDays(1).atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli();
            long notAfter = LocalDate.now().plusYears(1).atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli();
            BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuerDN, serialNumber,
                    new Date(notBefore), new Date(notAfter), issuerDN, publicKey);

            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);
            X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));

            // ??pem????
            StringBuilder certStringBuilder = new StringBuilder();
            certStringBuilder.append("-----BEGIN CERTIFICATE-----\n");
            certStringBuilder.append(new String(Base64.getMimeEncoder(64, new byte[]{'\n'}).encode(cert.getEncoded())));
            certStringBuilder.append("\n-----END CERTIFICATE-----\n");

            String certStr = certStringBuilder.toString();
            log.info("certStr: " + certStr);

            // ???????
            FileWriter fileWriter = new FileWriter(certPath);
            fileWriter.write(certStr);
            fileWriter.close();
        } catch (Exception e) {
            log.warn("Generate cert error", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * ????
     *
     * @return ??
     */
    public static PrivateKey readPrivateKey(String path) {
        try {
            FileInputStream fileInputStream = new FileInputStream(path);
            byte[] encodedPrivateKey = new byte[fileInputStream.available()];
            fileInputStream.read(encodedPrivateKey);
            fileInputStream.close();
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
            return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            log.warn("Read private key error", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * ????
     *
     * @return ??
     */
    public static PublicKey readPublicKey(String path) {
        try {
            FileInputStream fileInputStream = new FileInputStream(path);
            byte[] encodedPublicKey = new byte[fileInputStream.available()];
            fileInputStream.read(encodedPublicKey);
            fileInputStream.close();
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedPublicKey);
            return KeyFactory.getInstance("RSA").generatePublic(keySpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.warn("Read public key error", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * ????
     *
     * @return ??
     */
    public static X509Certificate readCert(String path) {
        try {
            FileReader fileReader = new FileReader(path);
            PemObject pemObject = new PemReader(fileReader).readPemObject();
            fileReader.close();
            return new JcaX509CertificateConverter().getCertificate(new X509CertificateHolder(pemObject.getContent()));
        } catch (IOException | CertificateException e) {
            log.warn("Read cert error", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * ??????
     *
     * @param certPath ????
     * @return ??
     */
    public static Credential getCertCredential(String certPath) {
        return new BasicX509Credential(CertUtils.readCert(certPath));
    }

    /**
     * ??????
     *
     * @return ??
     */
    public static Credential getKeyCredential(String publicKeyPath, String privateKeyPath) {
        return new BasicCredential(CertUtils.readPublicKey(publicKeyPath),
                CertUtils.readPrivateKey(privateKeyPath));
    }
}
