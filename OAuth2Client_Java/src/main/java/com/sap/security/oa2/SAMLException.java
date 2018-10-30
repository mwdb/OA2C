package com.sap.security.oa2;

public class SAMLException extends Exception {
	private static final long serialVersionUID = -5259734164588340171L;

	public SAMLException(Exception rootException) {
		super(rootException);
	}

	public SAMLException(Error rootException) {
		super(rootException);
	}

	public SAMLException(String errorString) {
		super(errorString);
	}
}
