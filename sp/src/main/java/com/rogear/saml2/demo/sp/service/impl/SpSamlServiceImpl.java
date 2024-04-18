package com.rogear.saml2.demo.sp.service.impl;

import com.rogear.saml2.demo.common.CertUtils;
import com.rogear.saml2.demo.common.SamlUtils;
import com.rogear.saml2.demo.sp.service.SpSamlService;
import com.rogear.saml2.demo.sp.service.dto.SsoDto;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPRedirectDeflateDecoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.impl.AssertionConsumerServiceBuilder;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.SPSSODescriptorBuilder;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.UUID;

import static com.rogear.saml2.demo.common.Constants.*;

/**
 * @author Rogear2008
 * @since 4/18/24
 */
@Service
public class SpSamlServiceImpl implements SpSamlService {

    private static final Logger log = LoggerFactory.getLogger(SpSamlServiceImpl.class);

    static {
        try {
            // ???
            InitializationService.initialize();
        } catch (InitializationException e) {
            log.warn("Init saml error", e);
            throw new RuntimeException(e);
        }

        // ????
        File file = new File(SP_CERT_PATH);
        if (!file.exists()) {
            CertUtils.generateCert(SP_PRIVATE_KEY_PATH, SP_PUBLIC_KEY_PATH, SP_CERT_PATH);
        }
    }

    @Override
    public String getSpMetadata() {
        try {
            // ????
            FileReader fileReader = new FileReader(SP_CERT_PATH);
            String certStr = "";
            BufferedReader reader = new BufferedReader(fileReader);
            String line;
            while ((line = reader.readLine()) != null) {
                certStr += line;
            }

            // ??metadata
            EntityDescriptor spEntityDescriptor = new EntityDescriptorBuilder().buildObject();
            spEntityDescriptor.setEntityID(SP_ENTITY_ID);

            SPSSODescriptor spSsoDescriptor = new SPSSODescriptorBuilder().buildObject();
            spSsoDescriptor.addSupportedProtocol(SAMLConstants.SAML20_NS);
            spSsoDescriptor.setAuthnRequestsSigned(false);
            spSsoDescriptor.setWantAssertionsSigned(false);

            String simpleCertStr = certStr.replaceAll("\n", "")
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "");
            // ??
            KeyDescriptor signKeyDescriptor = SamlUtils.createKeyDescriptor(simpleCertStr, UsageType.SIGNING);
            spSsoDescriptor.getKeyDescriptors().add(signKeyDescriptor);

            // ??
            KeyDescriptor encryptDescriptor = SamlUtils.createKeyDescriptor(simpleCertStr, UsageType.ENCRYPTION);
            spSsoDescriptor.getKeyDescriptors().add(encryptDescriptor);

            // redirect acs ??????
            AssertionConsumerService redirectAcsService = new AssertionConsumerServiceBuilder().buildObject();
            redirectAcsService.setLocation(SP_ACS_REDIRECT_URL);
            redirectAcsService.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
            spSsoDescriptor.getAssertionConsumerServices().add(redirectAcsService);

            // post acs ??????
            AssertionConsumerService postAcsService = new AssertionConsumerServiceBuilder().buildObject();
            postAcsService.setLocation(SP_ACS_POST_URL);
            postAcsService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
            spSsoDescriptor.getAssertionConsumerServices().add(postAcsService);

            spEntityDescriptor.getRoleDescriptors().add(spSsoDescriptor);

            // ???xml
            String spMetadata = SamlUtils.entityToXml(spEntityDescriptor);

            // ?????
            FileWriter fileWriter = new FileWriter(SP_METADATA_PATH);
            fileWriter.write(spMetadata);
            fileWriter.flush();
            return spMetadata;
        } catch (Exception e) {
            log.warn("Get sp metadata error");
            throw new RuntimeException(e);
        }
    }

    /**
     * ?idp??????
     * @param response ??
     */
    @Override
    public void ssoToIdp(HttpServletResponse response) {
        try {
            // ??AuthnRequest
            AuthnRequest authnRequest = buildAuthnRequest();

            // ???????
            MessageContext messageContext = SamlUtils.buildMessageContext(SAMLConstants.SAML2_REDIRECT_BINDING_URI, IDP_SSO_REDIRECT_URL);
            messageContext.setMessage(authnRequest);
            // ??relayState
            messageContext.getSubcontext(SAMLBindingContext.class, true).setRelayState(RELAY_STATE);

            // ??
            SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
            // ??????
            signatureSigningParameters.setSigningCredential(CertUtils.getKeyCredential(SP_PUBLIC_KEY_PATH, SP_PRIVATE_KEY_PATH));
            // ????
            signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
            messageContext.getSubcontext(SecurityParametersContext.class, true)
                    .setSignatureSigningParameters(signatureSigningParameters);

            // ??HTTPRedirectDeflateEncoder?????????????IDP?redirect sso ??
            HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
            encoder.setMessageContext(messageContext);
            encoder.setHttpServletResponse(response);
            encoder.initialize();
            //???RFC1951?????????????????????Base64??
            encoder.encode();
        } catch (Exception e) {
            log.warn("Sso to idp error");
            throw new RuntimeException(e);
        }
    }

    /**
     * ?idp??slo
     *
     * @param username ???
     * @param response response
     */
    @Override
    public void sloToIdp(String username, HttpServletResponse response) {
        LogoutRequest logoutRequest = buildLogoutRequest(username);
        MessageContext messageContext = SamlUtils.buildMessageContext(SAMLConstants.SAML2_REDIRECT_BINDING_URI, IDP_SLO_REDIRECT_URL);
        // ??relayState
        messageContext.getSubcontext(SAMLBindingContext.class, true).setRelayState(RELAY_STATE);
        messageContext.setMessage(logoutRequest);

        // ??
        SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
        // ??????????
        signatureSigningParameters.setSigningCredential(CertUtils.getKeyCredential(SP_PUBLIC_KEY_PATH, SP_PRIVATE_KEY_PATH));
        // ????
        signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        messageContext.getSubcontext(SecurityParametersContext.class, true)
                .setSignatureSigningParameters(signatureSigningParameters);

        // ??LogoutRequest?idp
        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
        encoder.setMessageContext(messageContext);
        encoder.setHttpServletResponse(response);
        try {
            encoder.initialize();
            encoder.encode();
        } catch (ComponentInitializationException | MessageEncodingException e) {
            log.warn("Slo to idp error");
            throw new RuntimeException(e);
        }
    }

    @Override
    public void sloRedirect(String samlRequest, String relayState, String signature, String sigAlg, HttpServletRequest request) {
        log.info("samlRequest: " + samlRequest);
        log.info("relayState: " + relayState);
        log.info("signature: " + signature);
        log.info("sigAlg: " + sigAlg);
        try {
            HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
            decoder.setHttpServletRequest(request);
            decoder.initialize();
            decoder.decode();
            MessageContext<SAMLObject> messageContext = decoder.getMessageContext();
            LogoutResponse logoutResponse = (LogoutResponse) messageContext.getMessage();
            log.info("logoutResponse: " + SamlUtils.entityToXml(logoutResponse));
            // ????????
            if (logoutResponse.getStatus().getStatusCode().getValue().equals(StatusCode.SUCCESS)) {
                log.info("Logout success");
                request.getSession().removeAttribute(LOGIN_USERNAME);
            }
        } catch (Exception e) {
            log.warn("Slo redirect error");
            throw new RuntimeException(e);
        }
    }

    private AuthnRequest buildAuthnRequest() {
        AuthnRequest authnRequest = new AuthnRequestBuilder().buildObject();
        // ??id
        authnRequest.setID(UUID.randomUUID().toString());
        // ????
        authnRequest.setIssueInstant(new DateTime());
        // ????
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        // ??????
        authnRequest.setAssertionConsumerServiceURL(SP_ACS_POST_URL);
        // ????
        authnRequest.setDestination(IDP_SLO_REDIRECT_URL);

        NameIDPolicy nameIDPolicy = new NameIDPolicyBuilder().buildObject();
        // ??????
        nameIDPolicy.setAllowCreate(true);
        nameIDPolicy.setFormat(NameIDType.TRANSIENT);
        authnRequest.setNameIDPolicy(nameIDPolicy);

        // ?????
        authnRequest.setIssuer(SamlUtils.buildIssuer(SP_ENTITY_ID));

        return authnRequest;
    }

    private LogoutRequest buildLogoutRequest(String username) {
        LogoutRequest logoutRequest = new LogoutRequestBuilder().buildObject();
        logoutRequest.setID(UUID.randomUUID().toString());
        logoutRequest.setIssueInstant(new DateTime());
        logoutRequest.setIssuer(SamlUtils.buildIssuer(SP_ENTITY_ID));
        logoutRequest.setNameID(SamlUtils.buildNameID(username));
        return logoutRequest;
    }

    @Override
    public String acsPost(SsoDto ssoDto, HttpServletRequest request) {
        String originalSamlResponse = ssoDto.getSAMLResponse();
        log.info("Original samlResponse: " + originalSamlResponse);
        String relayState = ssoDto.getRelayState();
        log.info("relayState: " + relayState);

        HTTPPostDecoder decoder = new HTTPPostDecoder();
        decoder.setHttpServletRequest(request);
        try {
            decoder.initialize();
            decoder.decode();
            MessageContext<SAMLObject> messageContext = decoder.getMessageContext();
            Response samlResponse = (Response) messageContext.getMessage();

            // ??
            validateSignature(samlResponse);

            // ????????
            Assertion assertion = samlResponse.getAssertions().get(0);

            // ????
            Conditions conditions = assertion.getConditions();
            DateTime notBefore = conditions.getNotBefore();
            DateTime notOnOrAfter = conditions.getNotOnOrAfter();
            if (notBefore.isAfterNow() || notOnOrAfter.isBeforeNow()) {
                throw new IllegalArgumentException("Assertion is not valid yet");
            }

            // ?????
            Issuer issuer = assertion.getIssuer();
            if (!issuer.getValue().equals(IDP_ENTITY_ID)) {
                throw new IllegalArgumentException("Assertion issuer is not valid");
            }

            NameID nameID = assertion.getSubject().getNameID();
            log.info("SSO username: " + nameID.getValue());
            // ??????
            request.getSession().setAttribute(LOGIN_USERNAME, nameID.getValue());

            // ???xml
            String samlResponseStr = SamlUtils.entityToXml(samlResponse);
            log.info("SAMLResponse?\n" + samlResponseStr);

            return "redirect:/sp/index";
        } catch (Exception e) {
            log.warn("Acs post error", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * ??
     *
     * @param samlResponse samlResponse
     */
    private void validateSignature(Response samlResponse) {
        if (!samlResponse.isSigned()) {
            throw new IllegalArgumentException("SAMLResponse is not signed");
        }
        SignableSAMLObject signableSAMLObject = (SignableSAMLObject) samlResponse;
        try {
            SignatureValidator.validate(signableSAMLObject.getSignature(), CertUtils.getCertCredential(IDP_CERT_PATH));
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }
}
