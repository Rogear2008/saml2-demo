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
     * 获取sp元数据
     *
     * @return sp元数据
     */
    String getSpMetadata();

    /**
     * POST方式断言消费
     *
     * @param ssoDto  ssoDto
     * @param request request
     * @return acs post
     */
    String acsPost(SsoDto ssoDto, HttpServletRequest request);

    /**
     * 向idp发起单点登录
     *
     * @param response response
     */
    void ssoToIdp(HttpServletResponse response);

    /**
     * 向idp发起单点登出
     *
     * @param username ???
     * @param response response
     */
    void sloToIdp(String username, HttpServletResponse response);

    /**
     * Redirect方式单点登出
     *
     * @param samlRequest saml请求
     * @param relayState  relayState
     * @param signature   签名
     * @param sigAlg      签名算法
     * @param request     http请求
     */
    void sloRedirect(String samlRequest, String relayState, String signature, String sigAlg, HttpServletRequest request);
}
