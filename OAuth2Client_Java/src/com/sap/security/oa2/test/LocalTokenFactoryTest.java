package com.sap.security.oa2.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Properties;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.sap.security.oa2.LocalSamlTokenFactory;
import com.sap.security.oa2.OAuth2SAML2AccessToken;
import com.sap.security.oa2.TrustData;
import com.sap.security.oa2.trace.OAuthTraceData;
import com.sap.security.oa2.trace.OAuthTracer;

public class LocalTokenFactoryTest {

    LocalSamlTokenFactory f;
    Properties configurationProperties;

    @Before
    public void setUp() throws IOException, NoSuchAlgorithmException, KeyManagementException {
	configurationProperties = new Properties();
	configurationProperties.load(getClass().getResourceAsStream("saml.properties"));
	f = (LocalSamlTokenFactory) LocalSamlTokenFactory.getInstance(configurationProperties);
	// Install the all-trusting trust manager
	setIgnoreSSLErrors();
    }

    public void setIgnoreSSLErrors() throws NoSuchAlgorithmException, KeyManagementException {
	TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {

	    public java.security.cert.X509Certificate[] getAcceptedIssuers() {

		return null;
	    }

	    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
	    }

	    public void checkServerTrusted(X509Certificate[] certs, String authType) {
	    }

	} };
	SSLContext sc = SSLContext.getInstance("SSL");

	sc.init(null, trustAllCerts, new java.security.SecureRandom());

	HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    };

    @Test
    public void dumpSAML2Metadata() throws Exception {
	System.out.println("SAML2 Metadata");
	new TrustData(configurationProperties).createMetadata(System.out);
	System.out.println();
    }

    @Test
    public void testGetAT2() throws Exception {
	try {
	    OAuth2SAML2AccessToken atf = new OAuth2SAML2AccessToken(f, configurationProperties);
	    String at = atf.getAccessToken("OAUTH2_TEST_SCOPE1 ZRMTSAMPLEFLIGHT_2_0001");
	    System.out.println(at);
	    Assert.assertTrue(at != null);
	} catch (Exception ex) {
	    ex.printStackTrace();
	    dumpTraces();
	    Assert.assertFalse("no access token received", true);
	}
	dumpTraces();

	// usage of an access token
	/*
	 * String url =
	 * "https://vete2012nwmst.fair.sap.corp:50443/sap/opu/odata/IWBEP/RMTSAMPLEFLIGHT_2/BookingCollection"
	 * ; HttpURLConnection con = (HttpURLConnection) new
	 * URL(url).openConnection(); con.addRequestProperty("Authorization",
	 * "Bearer " + at); con.setDoOutput(true); con.setDoInput(true);
	 * con.setRequestProperty("Cookie", ""); con.setRequestMethod("GET");
	 * InputStream is = null; int respCode = con.getResponseCode(); if
	 * (respCode != 200) { is = con.getErrorStream(); } else is =
	 * con.getInputStream(); ByteArrayOutputStream bos = new
	 * ByteArrayOutputStream(); int dataElement; while ((dataElement =
	 * is.read()) != -1) { bos.write(dataElement); } byte[] inData =
	 * bos.toByteArray(); System.out.println(bos);
	 */
    }

    /**
     * 
     */
    private void dumpTraces() {
	List<OAuthTraceData> traceDataList = OAuthTracer.getTraceData();
	for (OAuthTraceData td : traceDataList) {
	    if (td.getType() == OAuthTracer.TEXT_TYPE)
		System.out.println(td.getDescription() + ":" + td.getDataText());
	    if (td.getType() == OAuthTracer.XML_TYPE)
		System.out.println(td.getDescription() + ":" + new String(td.getData()));
	    if (td.getType() == OAuthTracer.HTTP_TYPE)
		System.out.println(td.getDescription() + ":" + new String(td.getData()));
	    System.out.println();
	}
    }

    private byte[] readData(InputStream is) throws IOException {
	ByteArrayOutputStream bos = new ByteArrayOutputStream();
	int dataElement;
	while ((dataElement = is.read()) != -1) {
	    bos.write(dataElement);
	}
	byte[] inData = bos.toByteArray();
	return inData;
    }
}
