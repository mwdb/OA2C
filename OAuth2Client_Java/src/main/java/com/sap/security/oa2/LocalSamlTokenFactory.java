package com.sap.security.oa2;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Properties;
import java.util.UUID;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml1.core.ConfirmationMethod;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AssertionMarshaller;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.KeyInfoBuilder;
import org.opensaml.xml.signature.impl.X509CertificateBuilder;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import com.sap.security.oa2.trace.OAuthTracer;

public class LocalSamlTokenFactory implements SamlTokenFactory {

    public static final String CFG_KEYSTORE_PATH = "ks_resource";
    public static final String CFG_KEYSTORE_TYPE = "ks_type";
    public static final String CFG_KEYSTORE_PASSWORD = "ks_pwd";
    public static final String CFG_KEYSTORE_ALIAS = "ks_alias";
    public static final String CFG_SAML_NAMEID = "saml_nameid";
    public static final String CFG_SAML_NAMEID_FORMAT = "saml_nameid_format";
    public static final String CFG_OA2_TOKEN_ENDPOINT = "oa2_token_endpoint";
    public static final String CFG_SAML_AUDIENCE_RESTRICTION = "saml_audience_restriction";
    public static final String CFG_SAML_ISSUER = "saml_issuer";
    public static final String CFG_SAML_AUTHNCONTEXT_PREVIUOUS_AUTHENTICATION = "saml_session_authentication";
    public static final String CFG_OA2_CLIENT_ID = "oa2_client_id";

    // OpenSAML object creation
    static private XMLObjectBuilderFactory builderFactory;
    private Credential _signingCredential;
    static private SAMLObjectBuilder<NameID> nameIdBuilder = null;
    static private SAMLObjectBuilder<ConfirmationMethod> confirmationMethodBuilder = null;
    static private SAMLObjectBuilder<SubjectConfirmation> subjectConfirmationBuilder = null;
    static private SAMLObjectBuilder<Subject> subjectBuilder = null;
    static private SAMLObjectBuilder<AudienceRestriction> audienceRestrictionnBuilder = null;
    static private SAMLObjectBuilder<Audience> audienceBuilder = null;
    static private SAMLObjectBuilder<AuthnStatement> authStatementBuilder = null;
    static private SAMLObjectBuilder<AuthnContext> authnContextBuilder = null;
    static private SAMLObjectBuilder<AuthnContextClassRef> authnContextClassRefBuilder = null;
    static private SAMLObjectBuilder<Issuer> issuerBuilder = null;
    static private SAMLObjectBuilder<Assertion> assertionBuilder = null;

    /**
     * Create instance object
     *
     * @param configurationProperties
     * @return
     * @throws ConfigurationException
     */
    public static SamlTokenFactory getInstance(Properties configurationProperties) throws ConfigurationException {
	getSAMLBuilder();
	return new LocalSamlTokenFactory(configurationProperties);
    }

    private LocalSamlTokenFactory(Properties configurationProperties) {
    }

    /**
     * Read signing key
     *
     * @return
     * @throws IOException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws UnrecoverableKeyException
     * @throws MissingPropertyException
     */
	private Credential getSigningCredential(Properties _cfg) throws IOException, KeyStoreException,
			NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, MissingPropertyException {
		if (this._signingCredential == null) { // check configuration
			checkPropertySet(_cfg, CFG_KEYSTORE_PATH);
			checkPropertySet(_cfg, CFG_KEYSTORE_PASSWORD);
			checkPropertySet(_cfg, CFG_KEYSTORE_ALIAS);
			// load keystore
			KeyStore ks = KeyStore.getInstance(getCfg(_cfg, CFG_KEYSTORE_TYPE, "JKS"));
			ks.load(getClass().getResourceAsStream(getCfg(_cfg, CFG_KEYSTORE_PATH)),
					getCfg(_cfg, CFG_KEYSTORE_PASSWORD).toCharArray());
			// load key data
			PrivateKey pk = (PrivateKey) ks.getKey(getCfg(_cfg, CFG_KEYSTORE_ALIAS),
					getCfg(_cfg, CFG_KEYSTORE_PASSWORD).toCharArray());
			X509Certificate pubKey = (X509Certificate) ks.getCertificate(getCfg(_cfg, CFG_KEYSTORE_ALIAS));
			OAuthTracer.trace(OAuthTracer.TEXT_TYPE, "Signing key", pubKey.getSubjectDN().getName());
			// create credential object
			Credential cred = SecurityHelper.getSimpleCredential(pubKey.getPublicKey(), pk);
			this._signingCredential = cred;
		}
		return this._signingCredential;
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
    private void checkPropertySet(Properties _cfg,String propertyName) throws MissingPropertyException {
	if (getCfg(_cfg,propertyName) == null)
	    throw new MissingPropertyException(propertyName);
    }

    /**
     * Builds a SAML Attribute of type String
     *
     * @param name
     * @param value
     * @param builderFactory
     * @return
     * @throws ConfigurationException
     */
    private Attribute buildStringAttribute(String name, String value, XMLObjectBuilderFactory builderFactory) throws ConfigurationException {
	SAMLObjectBuilder attrBuilder = (SAMLObjectBuilder) getSAMLBuilder().getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
	Attribute attrFirstName = (Attribute) attrBuilder.buildObject();
	attrFirstName.setName(name);

	// Set custom Attributes
	XMLObjectBuilder stringBuilder = getSAMLBuilder().getBuilder(XSString.TYPE_NAME);
	XSString attrValueFirstName = (XSString) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
	attrValueFirstName.setValue(value);

	attrFirstName.getAttributeValues().add(attrValueFirstName);
	return attrFirstName;
    }

    private static XMLObjectBuilderFactory getSAMLBuilder() throws ConfigurationException {
	if (builderFactory == null) {
	    // OpenSAML 2.3
	    DefaultBootstrap.bootstrap();
	    builderFactory = Configuration.getBuilderFactory();
	    nameIdBuilder = (SAMLObjectBuilder<NameID>) getSAMLBuilder().getBuilder(NameID.DEFAULT_ELEMENT_NAME);
	    confirmationMethodBuilder = (SAMLObjectBuilder<ConfirmationMethod>) getSAMLBuilder().getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
	    subjectConfirmationBuilder =(SAMLObjectBuilder<SubjectConfirmation>) getSAMLBuilder().getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
	    subjectBuilder =(SAMLObjectBuilder<Subject>) getSAMLBuilder().getBuilder(Subject.DEFAULT_ELEMENT_NAME);
	    audienceRestrictionnBuilder =  (SAMLObjectBuilder<AudienceRestriction>) getSAMLBuilder().getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);
	    audienceBuilder =  (SAMLObjectBuilder<Audience>) getSAMLBuilder().getBuilder(Audience.DEFAULT_ELEMENT_NAME);
	    authStatementBuilder =  (SAMLObjectBuilder<AuthnStatement>) getSAMLBuilder().getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
	    authnContextBuilder =  (SAMLObjectBuilder<AuthnContext>) getSAMLBuilder().getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
	    authnContextClassRefBuilder =(SAMLObjectBuilder<AuthnContextClassRef>) getSAMLBuilder().getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
	    issuerBuilder = (SAMLObjectBuilder<Issuer>) getSAMLBuilder().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
	    assertionBuilder =  (SAMLObjectBuilder<Assertion>) getSAMLBuilder().getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
	}

	return builderFactory;
    }

    /**
     * Helper method which includes some basic SAML fields which are part of
     * almost every SAML Assertion.
     *
     * @param input
     * @return
     * @throws MissingPropertyException
     * @throws ConfigurationException
     */
    private Assertion createAssertion(Properties _cfg) throws MissingPropertyException, ConfigurationException {
	checkPropertySet(_cfg,CFG_SAML_NAMEID);
	checkPropertySet(_cfg,CFG_OA2_TOKEN_ENDPOINT);
	checkPropertySet(_cfg,CFG_SAML_AUDIENCE_RESTRICTION);
	checkPropertySet(_cfg,CFG_SAML_ISSUER);
	checkPropertySet(_cfg,CFG_OA2_CLIENT_ID);

	// Create the NameIdentifier

	NameID nameId = nameIdBuilder.buildObject();
	nameId.setValue(getCfg(_cfg,CFG_SAML_NAMEID));
	nameId.setFormat(getCfg(_cfg,CFG_SAML_NAMEID_FORMAT, "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"));

	// Create the SubjectConfirmation

	SubjectConfirmationData confirmationMethod = (SubjectConfirmationData) confirmationMethodBuilder.buildObject();

	DateTime now = new DateTime();
	DateTime until = new DateTime().plusHours(4);

	// confirmationMethod.setNotBefore(now);
	confirmationMethod.setNotOnOrAfter(until);
	confirmationMethod.setRecipient(getCfg(_cfg,CFG_OA2_TOKEN_ENDPOINT));
	SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();

	subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
	subjectConfirmation.setSubjectConfirmationData(confirmationMethod);

	// should be Bearer

	// Create the Subject
	Subject subject = subjectBuilder.buildObject();

	subject.setNameID(nameId);
	subject.getSubjectConfirmations().add(subjectConfirmation);

	// Create the audience restriction
	AudienceRestriction audienceRestriction = audienceRestrictionnBuilder.buildObject();

	// Create the audience
	Audience audience = audienceBuilder.buildObject();
	audience.setAudienceURI(getCfg(_cfg,CFG_SAML_AUDIENCE_RESTRICTION));
	// add in the audience
	audienceRestriction.getAudiences().add(audience);

	SAMLObjectBuilder<Conditions> conditionsBuilder = (SAMLObjectBuilder<Conditions>) getSAMLBuilder().getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
	Conditions conditions = conditionsBuilder.buildObject();

    //conditions.getConditions().add(condition);
    conditions.getAudienceRestrictions().add(audienceRestriction);
	//conditions.setNotBefore(now);
	//conditions.setNotOnOrAfter(until);

	// Authnstatement

	AuthnStatement authnStatement = authStatementBuilder.buildObject();
	// authnStatement.setSubject(subject);
	// authnStatement.setAuthenticationMethod(strAuthMethod);
	DateTime now2 = new DateTime();
	authnStatement.setAuthnInstant(now2);
	// authnStatement.setSessionIndex(input.getSessionId());
	// authnStatement.setSessionNotOnOrAfter(now2.plus(15));

	AuthnContext authnContext = authnContextBuilder.buildObject();

	AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject();
	authnContextClassRef.setAuthnContextClassRef(getCfg(_cfg,CFG_SAML_AUTHNCONTEXT_PREVIUOUS_AUTHENTICATION, "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"));

	authnContext.setAuthnContextClassRef(authnContextClassRef);
	authnStatement.setAuthnContext(authnContext);

	// Create Issuer
	Issuer issuer = issuerBuilder.buildObject();
	issuer.setValue(getCfg(_cfg,CFG_SAML_ISSUER));

	// Create the attribute
	AttributeStatementBuilder attributeStatementBuilder = (AttributeStatementBuilder) builderFactory.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
	AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();

	AttributeBuilder attributeBuilder = (AttributeBuilder) builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
	Attribute attr = attributeBuilder.buildObject();
	attr.setName("client_id");

	XSAnyBuilder sb2 = (XSAnyBuilder) builderFactory.getBuilder(XSAny.TYPE_NAME);
	XSAny attrAny = sb2.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSAny.TYPE_NAME);
	attrAny.setTextContent(getCfg(_cfg,CFG_OA2_CLIENT_ID));

	attr.getAttributeValues().add(attrAny);
	attributeStatement.getAttributes().add(attr);

	// Create the assertion
	Assertion assertion = assertionBuilder.buildObject();
	assertion.setID("_" + UUID.randomUUID().toString());
	assertion.setSubject(subject);
	assertion.setIssuer(issuer);
	assertion.setIssueInstant(now);
	assertion.getAttributeStatements().add(attributeStatement);
	assertion.getAuthnStatements().add(authnStatement);
	assertion.setVersion(SAMLVersion.VERSION_20);

	assertion.setConditions(conditions);

	return assertion;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.sap.security.oa2.SamlTokenFactory#getSamlAssertion()
     */
    @Override
    public String getSamlAssertion(Properties _cfg) throws SAMLException {
	try {
	    Assertion assertion = createAssertion(_cfg);
	    AssertionMarshaller marshaller = new AssertionMarshaller();
	    Element plaintextElement = marshaller.marshall(assertion);
	    String originalAssertionString = XMLHelper.nodeToString(plaintextElement);

	    Credential signingCredential = getSigningCredential(_cfg);

	    Signature signature = (Signature) getSAMLBuilder().getBuilder(Signature.DEFAULT_ELEMENT_NAME).buildObject(Signature.DEFAULT_ELEMENT_NAME);

	    signature.setSigningCredential(signingCredential);
	    signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
	    signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

	    KeyInfoBuilder keyInfoBuilder = (KeyInfoBuilder) getSAMLBuilder().getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME);
	    KeyInfo keyInfo = keyInfoBuilder.buildObject();

	    //X509DataBuilder x509databuilder = (X509DataBuilder) getSAMLBuilder().getBuilder(X509Data.DEFAULT_ELEMENT_NAME);

	    //X509Data x509Data = x509databuilder.buildObject();
	    X509CertificateBuilder x509CertificateBuilder = (X509CertificateBuilder) getSAMLBuilder().getBuilder(org.opensaml.xml.signature.X509Certificate.DEFAULT_ELEMENT_NAME);

	    org.opensaml.xml.signature.X509Certificate certXMLAssertion = x509CertificateBuilder.buildObject();

	    certXMLAssertion.setValue(Base64.encodeBytes(signingCredential.getPublicKey().getEncoded()));
	    //x509Data.getX509Certificates().add(certXMLAssertion);
	    //x509Data.getX509Certificates().add(e)
	    //keyInfo.getX509Datas().add(x509Data);
	    signature.setKeyInfo(keyInfo);

	    assertion.setSignature(signature);

	    Configuration.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);

	    Signer.signObject(signature);

	    plaintextElement = marshaller.marshall(assertion);
	    originalAssertionString = XMLHelper.nodeToString(plaintextElement);
	    OAuthTracer.trace(OAuthTracer.XML_TYPE, "SAML Assertion", originalAssertionString.getBytes());
	    return originalAssertionString;
	} catch (Exception ex) {
	    throw new SAMLException(ex);
	}
    }

}
