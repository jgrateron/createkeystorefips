package com.demo;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public class Utils 
{
	public static final long ONE_YEAR = 1000L * 60 * 60 * 24 * 365;

	/**
	 * 
	 */
	 public static PKCS10CertificationRequest createPkcs10Request(PrivateKey key, X509Certificate cert)
	 
			throws GeneralSecurityException, OperatorCreationException {

		ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BCFIPS").build(key);

		return new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=PKCS10 Example"), cert.getPublicKey())
				.build(signer);
	}
	/**
	 * 
	 */
	public static X509Certificate makeV3Certificate(PrivateKey caPrivateKey, PublicKey eePublicKey)
			throws GeneralSecurityException, CertIOException, OperatorCreationException 
	{
		X509v3CertificateBuilder v3CertBldr = new JcaX509v3CertificateBuilder(new X500Principal("CN=Cert V3 Example"),
				BigInteger.valueOf(System.currentTimeMillis()).multiply(BigInteger.valueOf(10)),
				new Date(System.currentTimeMillis() - 1000L * 5),
				new Date(System.currentTimeMillis() + ONE_YEAR), new X500Principal("CN=Cert V3 Example"),
				eePublicKey);
		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

		v3CertBldr.addExtension(Extension.subjectKeyIdentifier, false,
				extUtils.createSubjectKeyIdentifier(eePublicKey));

		v3CertBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

		JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BCFIPS");

		return new JcaX509CertificateConverter().setProvider("BCFIPS")
				.getCertificate(v3CertBldr.build(signerBuilder.build(caPrivateKey)));
	}
	/**
	 * 
	 */
	public static Date getNow()
	{
		return new Date(System.currentTimeMillis());
	}
	/**
	 * 
	 */
	public static String dateTimeToStr(Date fecha)
	{
		SimpleDateFormat df = new SimpleDateFormat("yyyyMMddHHmm");
		return df.format(fecha);
	}
}
