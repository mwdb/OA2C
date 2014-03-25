package com.sap.security.oa2;

public class SAMLException extends Exception {
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
