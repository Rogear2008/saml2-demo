package com.rogear.saml2.demo.sp.controller;


import com.rogear.saml2.demo.sp.service.SpSamlService;
import com.rogear.saml2.demo.sp.service.dto.SsoDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletRequest;

import static com.rogear.saml2.demo.common.Constants.METADATA;

/**
 * @author Rogear2008
 * @since 4/18/24
 */
@Controller
@RequestMapping("/sp")
public class SpSamlController {

    @Autowired
    private SpSamlService spSamlService;

    /**
     * ??SP???
     *
     * @return SP???
     */
    @RequestMapping(value = "/metadata", method = RequestMethod.GET)
    public String getSpMetadata(HttpServletRequest request) {
        String metadata = spSamlService.getSpMetadata();
        request.getSession().setAttribute(METADATA, metadata);
        return "metadata";
    }

    /**
     * ACS POST??
     *
     * @param ssoDto  ??????
     * @param request ??
     * @return
     */
    @RequestMapping(value = "/acs/post", method = RequestMethod.POST)
    public String acsPost(@ModelAttribute SsoDto ssoDto, HttpServletRequest request) {
        return spSamlService.acsPost(ssoDto, request);
    }

    /**
     * Redirect???slo????
     *
     * @param SAMLRequest saml??
     * @param RelayState  relayState
     * @param Signature   ??
     * @param SigAlg      ????
     * @param request     http??
     * @return
     */
    @RequestMapping(value = "/slo/redirect", method = RequestMethod.GET)
    public String sloRedirect(String SAMLRequest, String RelayState, String Signature, String SigAlg,
                              HttpServletRequest request) {
        spSamlService.sloRedirect(SAMLRequest, RelayState, Signature, SigAlg, request);
        // ??????????
        return "redirect:/sp/login";
    }
}
