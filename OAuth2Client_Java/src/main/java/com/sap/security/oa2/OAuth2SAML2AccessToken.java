package com.sap.security.oa2;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Properties;

import org.opensaml.xml.util.Base64;

import com.sap.security.oa2.trace.OAuthTracer;

public class OAuth2SAML2AccessToken {

	public static final String CFG_SAML_RECIPIENT = "oa2_token_endpoint";
	private static final String CFG_OAUTH_CLIENT_USERNAME = "oa2_client_id";
	private static final String CFG_OAUTH_CLIENT_PASSWORD = "oa2_client_secret";

	public static boolean sslIgnoreSet = false;
	SamlTokenFactory stf;

	public OAuth2SAML2AccessToken(SamlTokenFactory stf) {
		this.stf = stf;
	}

	/**
	 * Read value from configuration
	 *
	 * @param propertyName
	 * @param defaultValue
	 * @return
	 */
	private String getCfg(Properties _cfg, String propertyName, String defaultValue) {
		return _cfg.getProperty(propertyName, defaultValue);
	}

	/**
	 * Read value from configuration
	 *
	 * @param propertyName
	 * @return
	 */
	private String getCfg(Properties _cfg, String propertyName) {
		return _cfg.getProperty(propertyName);
	}

	/**
	 * Check if a required property exists. Throws exception otherwise
	 *
	 * @param propertyName
	 * @throws MissingPropertyException
	 */
	private void checkPropertySet(Properties _cfg, String propertyName) throws MissingPropertyException {
		if (getCfg(_cfg, propertyName) == null)
			throw new MissingPropertyException(propertyName);
	}

	public String getAccessToken(Properties _cfg, String scope) throws AccessTokenException {
		try {
			checkPropertySet(_cfg, CFG_SAML_RECIPIENT);
			checkPropertySet(_cfg, CFG_OAUTH_CLIENT_USERNAME);
			checkPropertySet(_cfg, CFG_OAUTH_CLIENT_PASSWORD);

			String assertionString = stf.getSamlAssertion(_cfg);
			String recipient = getCfg(_cfg, CFG_SAML_RECIPIENT);
			String oa2Username = getCfg(_cfg, CFG_OAUTH_CLIENT_USERNAME);
			String oa2Password = getCfg(_cfg, CFG_OAUTH_CLIENT_PASSWORD);

			String b64Data = URLEncoder.encode(Base64.encodeBytes(assertionString.getBytes()),
					"UTF-8");
			HttpURLConnection con = (HttpURLConnection) new URL(recipient).openConnection();
			String data = String.format(
					"client_id=%s&scope=%s&grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer&assertion=%s",
					oa2Username, scope, b64Data);
			con.addRequestProperty("Authorization",
					"Basic " + Base64.encodeBytes((oa2Username + ":" + oa2Password).getBytes()));
			con.setDoOutput(true);
			con.setDoInput(true);
			con.setRequestProperty("Cookie", "");
			con.setRequestMethod("POST");
			OutputStreamWriter wr = new OutputStreamWriter(con.getOutputStream());
			wr.write(data);
			wr.flush();
			wr.close();

			int respCode = con.getResponseCode();
			if (respCode != 200) {
				byte[] res = readData(con.getErrorStream());
				OAuthTracer.trace(OAuthTracer.HTTP_TYPE, "POST (" + respCode + ") to " + recipient,
						"\nREQ:\nPOST data: " + data + "\n\nRESP:\n" + new String(res) + "\n\nURL:\n" + recipient);
				OAuthTracer.trace(OAuthTracer.TEXT_TYPE, "OAuth", new String(res));
				throw new AccessTokenException(new String(res));
			} else {
				byte[] res = readData(con.getInputStream());
				OAuthTracer.trace(OAuthTracer.HTTP_TYPE, "POST (" + respCode + ") to " + recipient,
						"\nREQ:\nPOST data: " + data + "\n\nRESP:\n" + new String(res) + "\n\nURL:\n" + recipient);
				OAuthTracer.trace(OAuthTracer.TEXT_TYPE, "OAuth", new String(res));
				return new String(res);
			}
		} catch (IOException | MissingPropertyException | SAMLException ex) {
			throw new AccessTokenException(ex);
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
