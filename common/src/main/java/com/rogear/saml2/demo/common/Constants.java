package com.rogear.saml2.demo.common;

import java.io.File;

/**
 * @author Rogear2008
 * @since 4/18/24
 */
public interface Constants {

    /**
     * 父级路径
     */
    String PARENT_PATH = System.getProperty("user.dir") + File.separator + "relation";

    /**
     * IDP证书路径
     */
    String IDP_CERT_PATH = PARENT_PATH + File.separator + "temp" + File.separator + "idpCertificate.pem";

    /**
     * IDP公钥路径
     */
    String IDP_PUBLIC_KEY_PATH = PARENT_PATH + File.separator + "temp" + File.separator + "idpPublic.key";

    /**
     * IDP私钥路径
     */
    String IDP_PRIVATE_KEY_PATH = PARENT_PATH + File.separator + "temp" + File.separator + "idpPrivate.key";

    /**
     * IDP元数据路径
     */
    String IDP_METADATA_PATH = PARENT_PATH + File.separator + "temp" + File.separator + "idpMetadata.xml";

    /**
     * SP证书路径
     */
    String SP_CERT_PATH = PARENT_PATH + File.separator + "temp" + File.separator + "spCertificate.pem";

    /**
     * SP公钥路径
     */
    String SP_PUBLIC_KEY_PATH = PARENT_PATH + File.separator + "temp" + File.separator + "spPublic.key";

    /**
     * SP私钥路径
     */
    String SP_PRIVATE_KEY_PATH = PARENT_PATH + File.separator + "temp" + File.separator + "spPrivate.key";

    /**
     * SP元数据路径
     */
    String SP_METADATA_PATH = PARENT_PATH + File.separator + "temp" + File.separator + "spMetadata.xml";

    /**
     * IDP的EntityID
     */
    String IDP_ENTITY_ID = "http://localhost:8585/idp";

    /**
     * IDP单点登录Redirect方式地址L
     */
    String IDP_SSO_REDIRECT_URL = "http://localhost:8585/idp/sso/redirect";

    /**
     * IDP单点登录 POST方式地址
     */
    String IDP_SSO_POST_URL = "http://localhost:8585/idp/sso/post";

    /**
     * IDP单点登出Redirect方式地址
     */
    String IDP_SLO_REDIRECT_URL = "http://localhost:8585/idp/slo/redirect";

    /**
     * IDP单点登出POST方式地址
     */
    String IDP_SLO_POST_URL = "http://localhost:8585/idp/slo/post";

    /**
     * SP的EntityId
     */
    String SP_ENTITY_ID = "http://localhost:8686/sp";

    /**
     * SP断言消费地址
     */
    String SP_ACS_REDIRECT_URL = "http://localhost:8686/sp/acs/redirect";

    /**
     * SP单点登出Redirect方式地址
     */
    String SP_SLO_REDIRECT_URL = "http://localhost:8686/sp/slo/redirect";

    /**
     * SP断言消费POST方式地址
     */
    String SP_ACS_POST_URL = "http://localhost:8686/sp/acs/post";

    /**
     * 登录的用户名
     */
    String LOGIN_USERNAME = "loginUsername";

    /**
     * RelayState
     */
    String RELAY_STATE = "RelayState";

    /**
     * 单点登录到SP
     */
    String SSO_TO_SP = "ssoToSp";

    /**
     * 元数据
     */
    String METADATA = "metadata";
}
