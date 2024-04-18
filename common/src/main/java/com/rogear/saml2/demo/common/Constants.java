package com.rogear.saml2.demo.common;

import java.io.File;

/**
 * @author Rogear2008
 * @since 4/18/24
 */
public interface Constants {

    /**
     * ???
     */
    String PARENT_PATH = System.getProperty("user.dir") + File.separator + "relation" ;

    /**
     * idp????
     */
    String IDP_CERT_PATH = PARENT_PATH + File.separator + "temp" + File.separator + "idpCertificate.pem";

    /**
     * idp????
     */
    String IDP_PUBLIC_KEY_PATH = PARENT_PATH + File.separator + "temp" + File.separator + "idpPublic.key";

    /**
     * idp????
     */
    String IDP_PRIVATE_KEY_PATH = PARENT_PATH + File.separator + "temp" + File.separator + "idpPrivate.key";

    /**
     * idp?????
     */
    String IDP_METADATA_PATH = PARENT_PATH + File.separator + "temp" + File.separator + "idpMetadata.xml";

    /**
     * sp????
     */
    String SP_CERT_PATH = PARENT_PATH + File.separator + "temp" + File.separator + "spCertificate.pem";

    /**
     * sp????
     */
    String SP_PUBLIC_KEY_PATH = PARENT_PATH + File.separator + "temp" + File.separator + "spPublic.key";

    /**
     * sp????
     */
    String SP_PRIVATE_KEY_PATH = PARENT_PATH + File.separator + "temp" + File.separator + "spPrivate.key";

    /**
     * sp?????
     */
    String SP_METADATA_PATH = PARENT_PATH + File.separator + "temp" + File.separator + "spMetadata.xml";

    /**
     * IDP??ID
     */
    String IDP_ENTITY_ID = "http://localhost:8585/idp";

    /**
     * IDP SSO???URL
     */
    String IDP_SSO_REDIRECT_URL = "http://localhost:8585/idp/sso/redirect";

    /**
     * IDP SSO POST URL
     */
    String IDP_SSO_POST_URL = "http://localhost:8585/idp/sso/post";

    /**
     * IDP SLO???URL
     */
    String IDP_SLO_REDIRECT_URL = "http://localhost:8585/idp/slo/redirect";

    /**
     * IDP SLO POST URL
     */
    String IDP_SLO_POST_URL = "http://localhost:8585/idp/slo/post";

    /**
     * SP??ID
     */
    String SP_ENTITY_ID = "http://localhost:8686/sp";

    /**
     * SP ACS???URL
     */
    String SP_ACS_REDIRECT_URL = "http://localhost:8686/sp/acs/redirect";

    /**
     * SP SLO???URL
     */
    String SP_SLO_REDIRECT_URL = "http://localhost:8686/sp/slo/redirect";

    /**
     * SP ACS POST URL
     */
    String SP_ACS_POST_URL = "http://localhost:8686/sp/acs/post";

    /**
     * ??????
     */
    String LOGIN_USERNAME = "loginUsername";

    /**
     * RelayState
     */
    String RELAY_STATE = "RelayState";
    /**
     * ?????SP
     */
    String SSO_TO_SP = "ssoToSp";

    /**
     * metadata
     */
    String METADATA = "metadata";
}
