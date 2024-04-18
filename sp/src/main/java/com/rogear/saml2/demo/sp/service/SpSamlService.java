package com.rogear.saml2.demo.sp.service;

import com.rogear.saml2.demo.sp.service.dto.SsoDto;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Rogear2008
 * @since 4/18/24
 */
public interface SpSamlService {

    /**
     * ??sp????
     *
     * @return sp????
     */
    String getSpMetadata();

    /**
     * ACS POST??
     *
     * @param ssoDto  ssoDto
     * @param request request
     * @return acs post
     */
    String acsPost(SsoDto ssoDto, HttpServletRequest request);

    /**
     * ?idp??sso
     *
     * @param response response
     */
    void ssoToIdp(HttpServletResponse response);

    /**
     * ?idp??slo
     *
     * @param username ???
     * @param response response
     */
    void sloToIdp(String username, HttpServletResponse response);

    /**
     * Redirect???slo????
     *
     * @param samlRequest saml??
     * @param relayState  relayState
     * @param signature   ??
     * @param sigAlg      ????
     * @param request     http??
     */
    void sloRedirect(String samlRequest, String relayState, String signature, String sigAlg, HttpServletRequest request);
}
