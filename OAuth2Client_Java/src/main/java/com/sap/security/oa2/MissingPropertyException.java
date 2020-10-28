package com.sap.security.oa2;

public class MissingPropertyException extends Exception {
	private static final long serialVersionUID = 9046938373553057581L;

	public MissingPropertyException(String missingProperty) {
		super("Missing property: " + missingProperty);
	}
}
