package com.jwt.test;
public class TokenException extends Exception {
	private int code;
	public TokenException(int code, String msg) {
		super(msg);
		this.code = code;
	}
	public int getCode() {
		return code;
	}
	public void setCode(int code) {
		this.code = code;
	}
}