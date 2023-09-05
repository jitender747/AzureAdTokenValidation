package com.jwt.test;

import java.io.Serializable;

/**
 * This POJO class specific to Azure B2C Security, even the attributes name
 */
public class OpenIdKeysBean implements Serializable {
	private static final long serialVersionUID = 1L;
	public java.util.List<KeyBean> getKeys() {
		return keys;
	}
	public void setKeys(java.util.List<KeyBean> keys) {
		this.keys = keys;
	}
	private java.util.List<KeyBean> keys;
}
