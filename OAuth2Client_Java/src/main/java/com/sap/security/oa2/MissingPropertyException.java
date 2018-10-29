package com.sap.security.oa2;

public class MissingPropertyException extends Exception {
    public MissingPropertyException(String missingProperty) {
	super("Missing property: " + missingProperty);
    }
}
