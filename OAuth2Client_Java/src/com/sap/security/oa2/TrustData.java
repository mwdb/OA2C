package com.sap.security.oa2;

import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Properties;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.opensaml.xml.util.Base64;

public class TrustData {
    Properties cfg;

    public TrustData(Properties cfg) {
	this.cfg = cfg;
    }

    public X509Certificate getSigningCertificate() throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {

	String keystorePath = cfg.getProperty(LocalSamlTokenFactory.CFG_KEYSTORE_PATH);
	String keystorePW = cfg.getProperty(LocalSamlTokenFactory.CFG_KEYSTORE_PASSWORD);
	String keyName = cfg.getProperty(LocalSamlTokenFactory.CFG_KEYSTORE_ALIAS);
	String ksType = cfg.getProperty(LocalSamlTokenFactory.CFG_KEYSTORE_TYPE);

	KeyStore ks = KeyStore.getInstance(ksType);
	ks.load(TrustData.class.getResourceAsStream(keystorePath), keystorePW.toCharArray());

	java.security.cert.Certificate cert = ks.getCertificate(keyName);
	return (X509Certificate) cert;
    }

    private static void createMetadata(String samlIssuer, X509Certificate[] certs, OutputStream os) {

	try {
	    String mdTemplate = "<?xml version='1.0' encoding='UTF-8'?><m:EntityDescriptor entityID='$$$ISSUER$$$' xmlns:m='urn:oasis:names:tc:SAML:2.0:metadata'><m:RoleDescriptor xsi:type='fed:SecurityTokenServiceType' xmlns:fed='http://docs.oasis-open.org/wsfed/federation/200706' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' protocolSupportEnumeration='http://docs.oasis-open.org/ws-sx/ws-trust/200512 http://schemas.xmlsoap.org/ws/2005/02/trust http://docs.oasis-open.org/wsfed/federation/200706'><m:KeyDescriptor use='signing'><ds:KeyInfo xmlns:ds='http://www.w3.org/2000/09/xmldsig#'><ds:X509Data><ds:X509Certificate>$$$CERT$$$</ds:X509Certificate></ds:X509Data></ds:KeyInfo></m:KeyDescriptor><fed:TokenTypesOffered><fed:TokenType Uri='urn:oasis:names:tc:SAML:1.0:assertion'/></fed:TokenTypesOffered></m:RoleDescriptor></m:EntityDescriptor>";
	    String md = mdTemplate.replace("$$$ISSUER$$$", samlIssuer);
	    String certB64;

	    certB64 = Base64.encodeBytes((certs[certs.length - 1].getEncoded()));
	    md = md.replace("$$$CERT$$$", certB64);
	    os.write(md.getBytes());
	} catch (Exception ex) {
	    Logger.getLogger(TrustData.class.getName()).log(Level.WARN, null, ex);
	}
    }

    public void createMetadata(OutputStream os) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
	createMetadata(getSAMLIssuer(), new X509Certificate[] { getSigningCertificate() }, os);
    }

    public String getSAMLIssuer() throws IOException {

	String samlIssuer = cfg.getProperty(LocalSamlTokenFactory.CFG_SAML_ISSUER);
	return samlIssuer;
    }

}
