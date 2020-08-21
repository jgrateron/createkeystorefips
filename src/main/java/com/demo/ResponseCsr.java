package com.demo;

public class ResponseCsr 
{
	private boolean success;
	private String pkcs7_der_base64;
	
	public boolean isSuccess() {
		return success;
	}
	public void setSuccess(boolean success) {
		this.success = success;
	}
	public String getPkcs7_der_base64() {
		return pkcs7_der_base64;
	}
	public void setPkcs7_der_base64(String pkcs7_der_base64) {
		this.pkcs7_der_base64 = pkcs7_der_base64;
	}
}
