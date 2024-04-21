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
     * 获取SP元数据
     *
     * @return SP元数据
     */
    @RequestMapping(value = "/metadata", method = RequestMethod.GET)
    public String getSpMetadata(HttpServletRequest request) {
        String metadata = spSamlService.getSpMetadata();
        request.getSession().setAttribute(METADATA, metadata);
        return "metadata";
    }

    /**
     * POST方式的断言消费
     *
     * @param ssoDto  单点登录对象
     * @param request 请求
     * @return
     */
    @RequestMapping(value = "/acs/post", method = RequestMethod.POST)
    public String acsPost(@ModelAttribute SsoDto ssoDto, HttpServletRequest request) {
        return spSamlService.acsPost(ssoDto, request);
    }

    /**
     * Redirect方式单点登出
     *
     * @param SAMLRequest saml请求
     * @param RelayState  relayState
     * @param Signature   签名
     * @param SigAlg      签名算法
     * @param request     http请求
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
