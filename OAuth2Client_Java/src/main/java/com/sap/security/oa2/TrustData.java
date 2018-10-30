package com.sap.security.oa2;

import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.Properties;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensaml.xml.util.Base64;

public class TrustData {
	Properties cfg;
	protected static final Logger LOG = LogManager.getLogger();

	public TrustData(Properties cfg) {
		this.cfg = cfg;
	}

	public X509Certificate getSigningCertificate()
			throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {

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
			String mdTemplate = "<?xml version='1.0' encoding='UTF-8'?>\r\n" +
					"<m:EntityDescriptor entityID='{0}' xmlns:m='urn:oasis:names:tc:SAML:2.0:metadata'>\r\n" +
					"	<m:RoleDescriptor xsi:type='fed:SecurityTokenServiceType' xmlns:fed='http://docs.oasis-open.org/wsfed/federation/200706' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' protocolSupportEnumeration='http://docs.oasis-open.org/ws-sx/ws-trust/200512 http://schemas.xmlsoap.org/ws/2005/02/trust http://docs.oasis-open.org/wsfed/federation/200706'>\r\n" +
					"		<m:KeyDescriptor use='signing'>\r\n" +
					"			<ds:KeyInfo xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>\r\n" +
					"				<ds:X509Data>\r\n" +
					"					<ds:X509Certificate>{1}</ds:X509Certificate>\r\n" +
					"				</ds:X509Data>\r\n" +
					"			</ds:KeyInfo>\r\n" +
					"		</m:KeyDescriptor>\r\n" +
					"		<fed:TokenTypesOffered>\r\n" +
					"			<fed:TokenType Uri='urn:oasis:names:tc:SAML:1.0:assertion'/>\r\n" +
					"		</fed:TokenTypesOffered>\r\n" +
					"	</m:RoleDescriptor>\r\n" +
					"</m:EntityDescriptor>";

			String certB64 = Base64.encodeBytes((certs[certs.length - 1].getEncoded()));
			String metadata = MessageFormat.format(mdTemplate, samlIssuer, certB64);

			os.write(metadata.getBytes());
		} catch (IOException e) {
			LOG.error("Couldn't create the metadata file", e);
		} catch (CertificateEncodingException e) {
			LOG.error("Couldn't encode the certificate", e);
		}
	}

	public void createMetadata(OutputStream os)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		createMetadata(getSAMLIssuer(), new X509Certificate[] { getSigningCertificate() }, os);
	}

	public String getSAMLIssuer() throws IOException {
		String samlIssuer = cfg.getProperty(LocalSamlTokenFactory.CFG_SAML_ISSUER);
		return samlIssuer;
	}
}
