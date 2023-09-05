package com.jwt.test;

import java.io.Serializable;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * This POJO class specific to Azure B2C Security, even the attributes name
 */
public class KeyBean implements Serializable {
	private static final long serialVersionUID = 1L;
	@JsonProperty("kty")
	private String keyType;
	@JsonProperty("use")
	private String keyUsage;
	@JsonProperty("kid")
	private String keyIdentifier;
	@JsonProperty("n")
	private String modulusByte;
	@JsonProperty("e")
	private String exponentByte;
	private java.util.List<String> x5c;
	private String issuer;
	public String getKeyType() {
		return keyType;
	}
	public void setKeyType(String keyType) {
		this.keyType = keyType;
	}
	public String getKeyUsage() {
		return keyUsage;
	}
	public void setKeyUsage(String keyUsage) {
		this.keyUsage = keyUsage;
	}
	public String getKeyIdentifier() {
		return keyIdentifier;
	}
	public void setKeyIdentifier(String keyIdentifier) {
		this.keyIdentifier = keyIdentifier;
	}
	public String getModulusByte() {
		return modulusByte;
	}
	public void setModulusByte(String modulusByte) {
		this.modulusByte = modulusByte;
	}
	public String getExponentByte() {
		return exponentByte;
	}
	public void setExponentByte(String exponentByte) {
		this.exponentByte = exponentByte;
	}
	public java.util.List<String> getX5c() {
		return x5c;
	}
	public void setX5c(java.util.List<String> x5c) {
		this.x5c = x5c;
	}
	public String getIssuer() {
		return issuer;
	}
	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}
}
