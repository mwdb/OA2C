package com.sap.security.oa2;


public interface SamlTokenFactory {

    public abstract String getSamlAssertion() throws SAMLException;

}