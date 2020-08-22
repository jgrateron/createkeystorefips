package com.demo;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public class Utils {
	public static final long ONE_YEAR = 1000L * 60 * 60 * 24 * 365;
	public static final String SIGNATURE_ALGORITHM_RSA = "SHA256withRSA";
	public static final String SIGNATURE_ALGORITHM_EC = "SHA256withECDSA";

	/**
	 * 
	 */
	public static PKCS10CertificationRequest createPkcs10Request(String signature_algorithm, KeyPair kp)

			throws GeneralSecurityException, OperatorCreationException {

		ContentSigner signer = new JcaContentSignerBuilder(signature_algorithm).setProvider("BCFIPS")
				.build(kp.getPrivate());

		return new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=PKCS10 Example"), kp.getPublic())
				.build(signer);
	}

	/**
	 * 
	 */
	public static Date getNow() {
		return new Date(System.currentTimeMillis());
	}

	/**
	 * 
	 */
	public static String dateTimeToStr(Date fecha) {
		SimpleDateFormat df = new SimpleDateFormat("yyyyMMddHHmm");
		return df.format(fecha);
	}
}
