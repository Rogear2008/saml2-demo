package com.rogear.saml2.demo.common;

import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml.saml2.metadata.*;
import org.opensaml.saml.saml2.metadata.impl.AssertionConsumerServiceBuilder;
import org.opensaml.saml.saml2.metadata.impl.KeyDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.SingleLogoutServiceBuilder;
import org.opensaml.saml.saml2.metadata.impl.SingleSignOnServiceBuilder;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.impl.KeyInfoBuilder;
import org.opensaml.xmlsec.signature.impl.X509CertificateBuilder;
import org.opensaml.xmlsec.signature.impl.X509DataBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;

/**
 * @author Rogear2008
 * @since 4/18/24
 */
public abstract class SamlUtils {

    /**
     * 构建单点登出服务
     *
     * @param url     地址
     * @param binding 绑定
     * @return SingleLogoutService
     */
    public static SingleLogoutService createSingleLogoutService(String url, String binding) {
        SingleLogoutService singleLogoutService = new SingleLogoutServiceBuilder().buildObject();
        singleLogoutService.setBinding(binding);
        singleLogoutService.setLocation(url);
        return singleLogoutService;
    }

    /**
     * 构建单点登录服务
     *
     * @param url     地址
     * @param binding 绑定
     * @return SingleSignOnService
     */
    public static SingleSignOnService createSingleSignOnService(String url, String binding) {
        SingleSignOnService singleSignOnService = new SingleSignOnServiceBuilder().buildObject();
        singleSignOnService.setBinding(binding);
        singleSignOnService.setLocation(url);
        return singleSignOnService;
    }

    /**
     * 构建KeyDescriptor
     *
     * @param certStr  证书
     * @param usageType 使用类型
     * @return KeyDescriptor
     */
    public static KeyDescriptor createKeyDescriptor(String certStr, UsageType usageType) {
        KeyDescriptor signKeyDescriptor = new KeyDescriptorBuilder().buildObject();
        signKeyDescriptor.setUse(usageType);
        X509Data x509Data = new X509DataBuilder().buildObject();
        org.opensaml.xmlsec.signature.X509Certificate x509Certificate = new X509CertificateBuilder().buildObject();
        x509Certificate.setValue(certStr);
        x509Data.getX509Certificates().add(x509Certificate);
        KeyInfo keyInfo = new KeyInfoBuilder().buildObject();
        keyInfo.getX509Datas().add(x509Data);
        signKeyDescriptor.setKeyInfo(keyInfo);
        return signKeyDescriptor;
    }

    /**
     * 对象转成xml
     *
     * @param samlObject saml对象
     * @return xml对象
     */
    public static String entityToXml(SAMLObject samlObject) {
        MarshallerFactory marshallerFactory = ConfigurationService.get(XMLObjectProviderRegistry.class)
                .getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(samlObject);
        try {
            marshaller.marshall(samlObject);
            TransformerFactory transfac = TransformerFactory.newInstance();
            Transformer trans = transfac.newTransformer();
            trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            trans.setOutputProperty(OutputKeys.INDENT, "yes");
            StringWriter stringWriter = new StringWriter();
            StreamResult streamResult = new StreamResult(stringWriter);
            DOMSource source = new DOMSource(samlObject.getDOM());
            trans.transform(source, streamResult);
            String metadata = "<?xml version=\"1.0\"?>\n" + stringWriter.toString();
            return metadata;
        } catch (MarshallingException | TransformerException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    /**
     * 构建签名
     *
     * @param credential 凭证
     * @return Signature
     */
    public static Signature buildSignature(Credential credential) {
        Signature signature = (Signature) XMLObjectProviderRegistrySupport.getBuilderFactory()
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
                .buildObject(Signature.DEFAULT_ELEMENT_NAME);

        signature.setSigningCredential(credential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        KeyInfo keyInfo = (KeyInfo) XMLObjectProviderRegistrySupport.getBuilderFactory()
                .getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME)
                .buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);

        X509Data x509Data = (X509Data) XMLObjectProviderRegistrySupport.getBuilderFactory()
                .getBuilder(X509Data.DEFAULT_ELEMENT_NAME)
                .buildObject(X509Data.DEFAULT_ELEMENT_NAME);

        X509Certificate x509Certificate = (X509Certificate) XMLObjectProviderRegistrySupport.getBuilderFactory()
                .getBuilder(X509Certificate.DEFAULT_ELEMENT_NAME)
                .buildObject(X509Certificate.DEFAULT_ELEMENT_NAME);

        x509Data.getX509Certificates().add(x509Certificate);
        keyInfo.getX509Datas().add(x509Data);
        signature.setKeyInfo(keyInfo);

        return signature;
    }

    /**
     * 构建消息上下文
     *
     * @param binding  绑定
     * @param location 地址
     * @return 消息上下文
     */
    public static MessageContext buildMessageContext(String binding, String location) {
        MessageContext messageContext = new MessageContext();
        // 设置端点，如果是IDP就设置SP的地址，标识从IDP要跳转到SP的什么地址，反之亦然
        SAMLPeerEntityContext peerEntityContext = messageContext.getSubcontext(SAMLPeerEntityContext.class, true);
        SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
        endpointContext.setEndpoint(buildEndpoint(binding, location));
        return messageContext;
    }

    /**
     * 构建Issuer
     *
     * @param issuer 签发者
     * @return Issuer
     */
    public static Issuer buildIssuer(String issuer) {
        Issuer issuerObj = new IssuerBuilder().buildObject();
        issuerObj.setValue(issuer);
        return issuerObj;
    }

    /**
     * 构建NameID
     *
     * @param nameID 名称
     * @return NameID
     */
    public static NameID buildNameID(String nameID) {
        NameID nameIDObj = new NameIDBuilder().buildObject();
        nameIDObj.setValue(nameID);
        return nameIDObj;
    }

    /**
     * 构建Status
     *
     * @param statusValue 状态
     * @return
     */
    public static Status buildStatus(String statusValue) {
        StatusCode statusCode = new StatusCodeBuilder().buildObject();
        statusCode.setValue(statusValue);
        Status status = new StatusBuilder().buildObject();
        status.setStatusCode(statusCode);
        return status;
    }

    /**
     * 构建Endpoint
     *
     * @param binding  绑定
     * @param location 地址
     * @return Endpoint
     */
    public static Endpoint buildEndpoint(String binding, String location) {
        AssertionConsumerService assertionConsumerService = new AssertionConsumerServiceBuilder().buildObject();
        assertionConsumerService.setBinding(binding);
        assertionConsumerService.setLocation(location);
        return assertionConsumerService;
    }
}
