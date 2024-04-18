package com.rogear.saml2.demo.idp.service.impl;

import com.rogear.saml2.demo.common.CertUtils;
import com.rogear.saml2.demo.common.SamlUtils;
import com.rogear.saml2.demo.idp.service.IdpSamlService;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.apache.xml.security.Init;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPRedirectDeflateDecoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.*;
import org.opensaml.saml.saml2.metadata.*;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.IDPSSODescriptorBuilder;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.thymeleaf.util.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.UUID;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import static com.rogear.saml2.demo.common.Constants.*;
import static com.rogear.saml2.demo.common.Constants.IDP_CERT_PATH;

/**
 * @author Rogear2008
 * @since 4/18/24
 */
@Service
public class IdpSamlServiceImpl implements IdpSamlService {

    private static final Logger log = LoggerFactory.getLogger(IdpSamlServiceImpl.class);

    static {
        try {
            // ???opensaml
            InitializationService.initialize();
        } catch (InitializationException e) {
            log.warn("Init saml error", e);
            throw new RuntimeException(e);
        }

        // ????
        File file = new File(IDP_CERT_PATH);
        if (!file.exists()) {
            CertUtils.generateCert(IDP_PRIVATE_KEY_PATH, IDP_PUBLIC_KEY_PATH, IDP_CERT_PATH);
        }
    }

    @Override
    public String getIdpMetadata() {
        try {
            // ????
            FileReader fileReader = new FileReader(IDP_CERT_PATH);
            String certStr = "";
            BufferedReader reader = new BufferedReader(fileReader);
            String line;
            while ((line = reader.readLine()) != null) {
                certStr += line;
            }

            // ??metadata
            EntityDescriptor idpEntityDescriptor = new EntityDescriptorBuilder().buildObject();
            idpEntityDescriptor.setEntityID(IDP_ENTITY_ID);

            IDPSSODescriptor idpSsoDescriptor = new IDPSSODescriptorBuilder().buildObject();
            idpSsoDescriptor.setWantAuthnRequestsSigned(false);
            idpSsoDescriptor.addSupportedProtocol(SAMLConstants.SAML20_NS);

            String simpleCertStr = certStr.replaceAll("\n", "")
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "");
            // ??
            KeyDescriptor signKeyDescriptor = SamlUtils.createKeyDescriptor(simpleCertStr, UsageType.SIGNING);
            idpSsoDescriptor.getKeyDescriptors().add(signKeyDescriptor);

            // ??
            KeyDescriptor encryptDescriptor = SamlUtils.createKeyDescriptor(simpleCertStr, UsageType.ENCRYPTION);
            idpSsoDescriptor.getKeyDescriptors().add(encryptDescriptor);

            // redirect sso ????????
            SingleSignOnService redirectSsoService = SamlUtils.createSingleSignOnService(
                    IDP_SSO_REDIRECT_URL, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
            idpSsoDescriptor.getSingleSignOnServices().add(redirectSsoService);

            // post sso Post??????
            SingleSignOnService postSsoService = SamlUtils.createSingleSignOnService(
                    IDP_SSO_POST_URL, SAMLConstants.SAML2_POST_BINDING_URI);
            idpSsoDescriptor.getSingleSignOnServices().add(postSsoService);

            // redirect slo ????????
            SingleLogoutService redirectSloService = SamlUtils.createSingleLogoutService(
                    IDP_SLO_REDIRECT_URL, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
            idpSsoDescriptor.getSingleLogoutServices().add(redirectSloService);

            // post slo Post??????
            SingleLogoutService postSloService = SamlUtils.createSingleLogoutService(
                    IDP_SLO_POST_URL, SAMLConstants.SAML2_POST_BINDING_URI);
            idpSsoDescriptor.getSingleLogoutServices().add(postSloService);

            idpEntityDescriptor.getRoleDescriptors().add(idpSsoDescriptor);

            // ???xml
            String idpMetadata = SamlUtils.entityToXml(idpEntityDescriptor);

            // ?????
            FileWriter fileWriter = new FileWriter(IDP_METADATA_PATH);
            fileWriter.write(idpMetadata);
            fileWriter.flush();
            return idpMetadata;
        } catch (Exception e) {
            log.warn("Get idp metadata error", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public String ssoRedirect(String samlRequest, String relayState, String signature, String sigAlg, HttpServletRequest request) {
        // ??????session?
        HttpSession session = request.getSession();
        session.setAttribute(SSO_TO_SP, true);
        log.info("samlRequest: " + samlRequest);
        log.info("relayState: " + relayState);
        log.info("signature: " + signature);
        log.info("sigAlg: " + sigAlg);
        try {
            // ??
            validateSamlRequest(samlRequest, relayState, signature, sigAlg);

            HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
            decoder.setHttpServletRequest(request);
            decoder.initialize();
            decoder.decode();
            MessageContext<SAMLObject> messageContext = decoder.getMessageContext();
            AuthnRequest authnRequest = (AuthnRequest) messageContext.getMessage();
            String authnRequestStr = SamlUtils.entityToXml(authnRequest);
            log.info("authnRequest: \n" + authnRequestStr);

            // ??????opensaml??? ?????
            getAuthnRequest(samlRequest);

            // ???AuthnRequest???????????????????????????sso?
            Issuer issuer = authnRequest.getIssuer();
            log.info("issuer: " + issuer.getValue());

            // ??????????
            return "redirect:/idp/login";
        } catch (Exception e) {
            log.warn("Sso redirect error", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * ??
     *
     * @param samlRequest saml??
     * @param relayState  relayState
     * @param signature   ??
     * @param sigAlg      ????
     */
    private void validateSamlRequest(String samlRequest, String relayState, String signature, String sigAlg) {
        // ????????
        if (StringUtils.isEmpty(signature)) {
            log.info("Signature is empty");
            return;
        }
        try {
            String query = "SAMLRequest=" + URLEncoder.encode(samlRequest, "UTF-8") + "&RelayState="
                    + URLEncoder.encode(relayState, "UTF-8") + "&SigAlg="
                    + URLEncoder.encode(sigAlg, "UTF-8");
            byte[] signatureBytes = Base64.getDecoder().decode(signature);
            Init.init();
            java.security.Signature sig;
            if (SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256.equals(sigAlg)) {
                sig = java.security.Signature.getInstance("SHA256withRSA");
            } else if (SignatureConstants.ALGO_ID_SIGNATURE_DSA_SHA1.equals(sigAlg)) {
                sig = java.security.Signature.getInstance("SHA1withDSA");
            } else {
                throw new RuntimeException("Unknown signature algorithm: " + sigAlg);
            }
            X509Certificate x509Certificate = CertUtils.readCert(SP_CERT_PATH);
            sig.initVerify(x509Certificate.getPublicKey());
            sig.update(query.getBytes());
            if (!sig.verify(signatureBytes)) {
                throw new RuntimeException("Signature is not valid");
            }
        } catch (Exception e) {
            log.warn("Signature is not valid");
            throw new RuntimeException(e);
        }
    }

    private AuthnRequest getAuthnRequest(String samlRequest) throws IOException, ParserConfigurationException, SAXException, UnmarshallingException, MarshallingException, TransformerException {
        // Base64 ?? SAMLRequest
        byte[] samlRequestDecodedBytes = Base64.getDecoder().decode(samlRequest);

        // ?? Inflater (???ZIP??)
        Inflater inflater = new Inflater(true);
        InflaterInputStream inflaterInputStream = new InflaterInputStream(new ByteArrayInputStream(samlRequestDecodedBytes), inflater);

        // ?InflaterInputStream?????????
        ByteArrayOutputStream decodedRequestOS = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = inflaterInputStream.read(buffer)) != -1) {
            decodedRequestOS.write(buffer, 0, bytesRead);
        }
        String decodedRequestString = decodedRequestOS.toString(StandardCharsets.UTF_8.name());
        log.info("decodedRequestString: \n" + decodedRequestString);


        // ?? SAMLRequest XML ???? DOM ??
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        Document document = documentBuilder.parse(new ByteArrayInputStream(decodedRequestString.getBytes(StandardCharsets.UTF_8)));
        Element element = document.getDocumentElement();

        // ?? UnmarshallerFactory ? ParserPool
        UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();

        // ? DOM ????? Unmarshaller
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);

        // ?? SAML??
        XMLObject xmlObject = unmarshaller.unmarshall(element);

        // ?XMLObject ???AuthnRequest
        AuthnRequest authnRequest = (AuthnRequest) xmlObject;

        String authnRequestStr = SamlUtils.entityToXml(authnRequest);
        log.info("authnRequest: \n" + authnRequestStr);
        return authnRequest;
    }

    @Override
    public void ssoToSp(String relayState, HttpServletRequest request, HttpServletResponse httpServletResponse) {
        HttpSession session = request.getSession();
        // ????
        session.removeAttribute(SSO_TO_SP);
        String username = (String) session.getAttribute(LOGIN_USERNAME);
        if (StringUtils.isEmpty(username)) {
            throw new RuntimeException("Haven't login");
        }
        MessageContext messageContext = SamlUtils.buildMessageContext(SAMLConstants.SAML2_POST_BINDING_URI, SP_ACS_POST_URL);
        // ??SAMLResponse
        Response response = buildSAMLResponse(username);
        messageContext.setMessage(response);
        // ??relayState
        messageContext.getSubcontext(SAMLBindingContext.class, true).setRelayState(relayState);

        try {
            HTTPPostEncoder encoder = new HTTPPostEncoder();
            encoder.setMessageContext(messageContext);
            encoder.setHttpServletResponse(httpServletResponse);

            // ??velocityEngine
            VelocityEngine velocityEngine = new VelocityEngine();
            velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
            velocityEngine.setProperty("classpath.resource.loader.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
            encoder.setVelocityEngine(velocityEngine);
//
//            // HTTPPostEncoder??????saml1????????saml2???
//            encoder.setVelocityTemplateId("/templates/saml2-post-binding.vm");
            encoder.initialize();

            // ???SP?ACS??
            encoder.encode();
        } catch (Exception e) {
            log.warn("ssoToSp error", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public void sloRedirect(String samlRequest, String relayState, String signature, String sigAlg,
                            HttpServletRequest request, HttpServletResponse response) {
        try {
            // ??
            validateSamlRequest(samlRequest, relayState, signature, sigAlg);
            HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
            decoder.setHttpServletRequest(request);
            decoder.initialize();
            decoder.decode();
            MessageContext<SAMLObject> messageContext = decoder.getMessageContext();
            LogoutRequest logoutRequest = (LogoutRequest) messageContext.getMessage();
            String logoutRequestStr = SamlUtils.entityToXml(logoutRequest);
            log.info("logoutRequest: \n" + logoutRequestStr);
            // ??????????
            String username = logoutRequest.getNameID().getValue();
            log.info("Logout username: " + username);
            // ??idp???????SP????????????????SP???
            request.getSession().removeAttribute(LOGIN_USERNAME);

            // ????
            responseLogout(relayState, response);
        } catch (Exception e) {
            log.warn("Slo redirect error", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * ??slo???
     *
     * @param relayState
     * @param response   ??
     */
    private void responseLogout(String relayState, HttpServletResponse response) {
        LogoutResponse logoutResponse = buildLogoutResponse();
        MessageContext messageContext = SamlUtils.buildMessageContext(SAMLConstants.SAML2_REDIRECT_BINDING_URI, SP_SLO_REDIRECT_URL);
        messageContext.setMessage(logoutResponse);
        // ??relayState
        messageContext.getSubcontext(SAMLBindingContext.class, true).setRelayState(relayState);

        // ??LogoutResponse?sp
        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
        encoder.setMessageContext(messageContext);
        encoder.setHttpServletResponse(response);
        try {
            encoder.initialize();
            encoder.encode();
        } catch (ComponentInitializationException | MessageEncodingException e) {
            log.warn("Slo to sp error", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * ??LogoutResponse
     *
     * @return LogoutResponse
     */
    private LogoutResponse buildLogoutResponse() {
        LogoutResponse logoutResponse = new LogoutResponseBuilder().buildObject();
        logoutResponse.setID(UUID.randomUUID().toString());
        logoutResponse.setIssueInstant(new DateTime());
        logoutResponse.setIssuer(SamlUtils.buildIssuer(IDP_ENTITY_ID));
        // ????
        logoutResponse.setStatus(SamlUtils.buildStatus(StatusCode.SUCCESS));
        return logoutResponse;
    }

    /**
     * ??SAMLResponse
     *
     * @param username ???
     * @return SAMLResponse
     */
    private Response buildSAMLResponse(String username) {
        Response response = new ResponseBuilder().buildObject();
        // ??id
        response.setID(UUID.randomUUID().toString());
        // ??????
        response.setIssueInstant(new DateTime());
        response.setVersion(SAMLVersion.VERSION_20);
        response.setStatus(SamlUtils.buildStatus(StatusCode.SUCCESS));
        // ????
        response.getAssertions().add(buildAssertion(username));

        // ??
        signResponse(response);
        return response;
    }

    /**
     * ??SAMLResponse
     *
     * @param response SAMLResponse
     */
    private void signResponse(Response response) {
        // ????
        Signature signature = SamlUtils.buildSignature(CertUtils.getKeyCredential(IDP_PUBLIC_KEY_PATH, IDP_PRIVATE_KEY_PATH));
        response.setSignature(signature);

        try {
            XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(response).marshall(response);
            // ????
            Signer.signObject(signature);
        } catch (MarshallingException | SignatureException e) {
            log.warn("Sign response error", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * ????
     *
     * @param username ???
     * @return ??
     */
    private Assertion buildAssertion(String username) {
        Assertion assertion = new AssertionBuilder().buildObject();
        assertion.setID(UUID.randomUUID().toString());
        assertion.setIssueInstant(new DateTime());

        // ?????
        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue(IDP_ENTITY_ID);
        assertion.setIssuer(issuer);

        // ??nameId
        NameID nameID = new NameIDBuilder().buildObject();
        nameID.setValue(username);
        nameID.setFormat(NameID.PERSISTENT);
        Subject subject = new SubjectBuilder().buildObject();
        subject.setNameID(nameID);
        assertion.setSubject(subject);

        // ????
        Conditions conditions = new ConditionsBuilder().buildObject();
        conditions.setNotBefore(new DateTime());
        conditions.setNotOnOrAfter(new DateTime().plusMinutes(10));
        assertion.setConditions(conditions);

        return assertion;
    }

}
