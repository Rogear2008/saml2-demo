package com.rogear.saml2.demo.idp.controller;

import com.rogear.saml2.demo.idp.service.IdpSamlService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static com.rogear.saml2.demo.common.Constants.METADATA;
import static com.rogear.saml2.demo.common.Constants.RELAY_STATE;
/**
 * @author Rogear2008
 * @since 4/18/24
 */
@Controller
@RequestMapping("/idp")
public class IdpSamlController {

    @Autowired
    private IdpSamlService idpSamlService;

    /**
     * ??IDP???
     *
     * @return IDP???
     */
    @RequestMapping(value = "/metadata", method = RequestMethod.GET)
    public String getIdpMetadata(HttpServletRequest request) {
        String metadata = idpSamlService.getIdpMetadata();
        request.getSession().setAttribute(METADATA, metadata);
        return "metadata";
    }

    /**
     * Redirect???sso????
     *
     * @param SAMLRequest saml????????????????
     * @param RelayState  relayState??????????????
     * @param request     http??
     * @return sso???
     */
    @GetMapping("/sso/redirect")
    public String ssoRedirect(String SAMLRequest, String RelayState, String Signature, String SigAlg,
                              HttpServletRequest request, RedirectAttributes redirectAttributes) {
        // saml??????????????
//        String samlRequest = request.getParameter("SAMLRequest");
//        String relayState = request.getParameter("RelayState");
        redirectAttributes.addAttribute(RELAY_STATE, RelayState);
        return idpSamlService.ssoRedirect(SAMLRequest, RelayState, Signature, SigAlg, request);
    }

    /**
     * Redirect???slo????
     *
     * @param SAMLRequest saml????????????????
     * @param RelayState  relayState??????????????
     * @param request     http??
     * @return slo???
     */
    @GetMapping("/slo/redirect")
    public void sloRedirect(String SAMLRequest, String RelayState, String Signature, String SigAlg,
                            HttpServletRequest request, HttpServletResponse response) {
        idpSamlService.sloRedirect(SAMLRequest, RelayState, Signature, SigAlg, request, response);
    }

    /**
     * ?????SP
     *
     * @param request  http??
     * @param response http??
     * @return
     */
    @RequestMapping(value = "sso_to_sp", method = RequestMethod.GET)
    public void ssoToSp(HttpServletRequest request, HttpServletResponse response) {
        idpSamlService.ssoToSp(null, request, response);
    }

}
