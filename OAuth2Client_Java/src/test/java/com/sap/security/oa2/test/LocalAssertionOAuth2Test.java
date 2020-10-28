package com.sap.security.oa2.test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Properties;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.sap.security.oa2.AccessTokenException;
import com.sap.security.oa2.LocalSamlTokenFactory;
import com.sap.security.oa2.OAuth2SAML2AccessToken;
import com.sap.security.oa2.TrustData;
import com.sap.security.oa2.trace.OAuthTraceData;
import com.sap.security.oa2.trace.OAuthTracer;

public class LocalAssertionOAuth2Test {

	protected static final Logger LOG = LogManager.getLogger();

	LocalSamlTokenFactory localSAMLTokenFactory;
	Properties configurationProperties;

	@Before
	public void setUp() throws Exception {
		try (InputStream samlPropsStream = this.getClass().getResourceAsStream("/test/resources/saml.properties")) {
			if (samlPropsStream == null) {
				throw new Exception("Cannot find /test/resources/saml.properties");
			}

			configurationProperties = new Properties();
			configurationProperties.load(samlPropsStream);
			localSAMLTokenFactory = (LocalSamlTokenFactory) LocalSamlTokenFactory.getInstance(configurationProperties);

			// Install the all-trusting trust manager
			setIgnoreSSLErrors();
		}
	}

	@Test
	/**
	 * Generate SAML Metadata based on the saml.properties file
	 *
	 * @throws Exception
	 */
	public void dumpSAML2Metadata() throws Exception {
		File f = new File("metadata.xml");
		try (FileOutputStream fos = new FileOutputStream(f)) {
			LOG.info("SAML2 Metadata:");
			new TrustData(configurationProperties).createMetadata(fos);

			String path = f.getAbsolutePath();
			LOG.info("Metadata written to: {}", path);
		}
	}

	@Test
	/**
	 * Obtain an access token from a Gateway system
	 *
	 * @throws Exception
	 */
	public void testGetAT2() {
		OAuth2SAML2AccessToken atf = new OAuth2SAML2AccessToken(localSAMLTokenFactory);
		LOG.info("Using the user name: {}", configurationProperties.getProperty("saml_nameid"));
		LOG.info("Using the scope: {}", configurationProperties.getProperty("scope"));
		try {
			// configurationProperties.remove("saml_nameid");
			// configurationProperties.setProperty("saml_nameid", "SAP_USER");
			// obtain access token for scope EPM_LANES_DEMO_SRV_0001
			// multiple scopes are separated by space, e.g. "EPM_LANES_DEMO_SRV_0001 EPM_SCOPE2"
			String at = atf.getAccessToken(configurationProperties, configurationProperties.getProperty("scope"));
			LOG.info("Access token: {}", at);

			Assert.assertTrue(at != null);
		} catch (AccessTokenException ex) {
			LOG.error("No access token received:", ex);
			Assert.assertFalse("No access token received", true);
		} finally {
			dumpTraces();
		}
		// usage of an access token
		/*
		String url = "https://vete2012nwmst.fair.sap.corp:50443/sap/opu/odata/IWBEP/RMTSAMPLEFLIGHT_2/BookingCollection";
		HttpURLConnection con = (HttpURLConnection) new URL(url).openConnection();
		con.addRequestProperty("Authorization", "Bearer " + at);
		con.setDoOutput(true);
		con.setDoInput(true);
		con.setRequestProperty("Cookie", "");
		con.setRequestMethod("GET");
		InputStream is = null;
		int respCode = con.getResponseCode();
		if (respCode != 200) {
			is = con.getErrorStream();
		} else
			is = con.getInputStream();
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		int dataElement;
		while ((dataElement = is.read()) != -1) {
			bos.write(dataElement);
		}
		byte[] inData = bos.toByteArray();
		System.out.println(bos);
		*/
	}

	/**
	 *
	 */
	private void dumpTraces() {
		List<OAuthTraceData> traceDataList = OAuthTracer.getTraceData();
		for (OAuthTraceData td : traceDataList) {
			if (td.getType() == OAuthTracer.TEXT_TYPE)
				LOG.info(td.getDescription() + ":" + td.getDataText());
			if (td.getType() == OAuthTracer.XML_TYPE)
				LOG.info(td.getDescription() + ":" + new String(td.getData()));
			if (td.getType() == OAuthTracer.HTTP_TYPE)
				LOG.info(td.getDescription() + ":" + new String(td.getData()));
		}
	}
/*
	private byte[] readData(InputStream is) throws IOException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		int dataElement;
		while ((dataElement = is.read()) != -1) {
			bos.write(dataElement);
		}
		byte[] inData = bos.toByteArray();
		return inData;
	}
*/
	public void setIgnoreSSLErrors() throws NoSuchAlgorithmException, KeyManagementException {
		TrustManager[] trustAllCerts = new TrustManager[] { new X509ExtendedTrustManager() {

			@Override
			public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
			}

			@Override
			public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
			}

			@Override
			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}

			@Override
			public void checkClientTrusted(X509Certificate[] arg0, String arg1, Socket arg2)
					throws CertificateException {
			}

			@Override
			public void checkClientTrusted(X509Certificate[] arg0, String arg1, SSLEngine arg2)
					throws CertificateException {
			}

			@Override
			public void checkServerTrusted(X509Certificate[] arg0, String arg1, Socket arg2)
					throws CertificateException {
			}

			@Override
			public void checkServerTrusted(X509Certificate[] arg0, String arg1, SSLEngine arg2)
					throws CertificateException {
			}
		} };

		SSLContext sc = SSLContext.getInstance("SSL");
		sc.init(null, trustAllCerts, new java.security.SecureRandom());
		HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
	};
}
