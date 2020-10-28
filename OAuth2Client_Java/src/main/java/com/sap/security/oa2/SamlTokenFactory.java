package com.sap.security.oa2;

import java.util.Properties;


public interface SamlTokenFactory {

    public abstract String getSamlAssertion(Properties cfgProperties) throws SAMLException;

}