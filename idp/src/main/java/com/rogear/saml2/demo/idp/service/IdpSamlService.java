package com.rogear.saml2.demo.idp.service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Rogear2008
 * @since 4/18/24
 */
public interface IdpSamlService {

    /**
     * 获取IDP元数据
     *
     * @return IDP元数据
     */
    String getIdpMetadata();

    /**
     * Redirect方式单点登录
     *
     * @param samlRequest saml请求
     * @param relayState  relayState
     * @param signature   签名
     * @param sigAlg      签名算法
     * @param request     http请求
     * @return 跳转地址
     */
    String ssoRedirect(String samlRequest, String relayState, String signature, String sigAlg, HttpServletRequest request);

    /**
     * sso到sp
     *
     * @param relayState relayState
     * @param request    http请求
     * @param response   http响应
     */
    void ssoToSp(String relayState, HttpServletRequest request, HttpServletResponse response);

    /**
     * 单点登出
     *
     * @param samlRequest saml请求
     * @param relayState  relayState
     * @param signature   签名
     * @param sigAlg      签名算法
     * @param request     http请求
     * @param response    http响应
     */
    void sloRedirect(String samlRequest, String relayState, String signature, String sigAlg, HttpServletRequest request, HttpServletResponse response);

}

