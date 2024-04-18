package com.rogear.saml2.demo.idp.service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Rogear2008
 * @since 4/18/24
 */
public interface IdpSamlService {

    /**
     * ??IDP???
     *
     * @return IDP???
     */
    String getIdpMetadata();

    /**
     * Redirect???sso
     *
     * @param samlRequest saml??
     * @param relayState  relayState
     * @param signature   ??
     * @param sigAlg      ????
     * @param request     http??
     * @return sso???
     */
    String ssoRedirect(String samlRequest, String relayState, String signature, String sigAlg, HttpServletRequest request);

    /**
     * sso?sp
     *
     * @param relayState relayState
     * @param request    http??
     * @param response   http??
     * @return
     */
    void ssoToSp(String relayState, HttpServletRequest request, HttpServletResponse response);

    /**
     * slo
     *
     * @param samlRequest saml??
     * @param relayState  relayState
     * @param signature   ??
     * @param sigAlg      ????
     * @param request     http??
     * @param response    http??
     */
    void sloRedirect(String samlRequest, String relayState, String signature, String sigAlg, HttpServletRequest request, HttpServletResponse response);

}

