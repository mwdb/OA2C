package com.sap.security.oa2;

public class AccessTokenException extends Exception {
	private static final long serialVersionUID = 8096113474565306878L;

	public AccessTokenException(Exception ex) {
		super(ex);
	}

	public AccessTokenException(String message) {
		super(message);
	}

}
