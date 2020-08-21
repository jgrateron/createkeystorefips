package com.demo;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class Certificado
{
	X509Certificate cert;
	PrivateKey key;
	
	public X509Certificate getCert() {
		return cert;
	}
	public void setCert(X509Certificate cert) {
		this.cert = cert;
	}
	public PrivateKey getKey() {
		return key;
	}
	public void setKey(PrivateKey key) {
		this.key = key;
	}
	public Certificado(X509Certificate cert, PrivateKey key) {
		super();
		this.cert = cert;
		this.key = key;
	}
}
