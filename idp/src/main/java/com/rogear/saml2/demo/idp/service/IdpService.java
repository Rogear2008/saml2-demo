package com.rogear.saml2.demo.idp.service;

import com.rogear.saml2.demo.common.dto.LoginDto;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Rogear2008
 * @since 4/18/24
 */
public interface IdpService {

    /**
     * 登录
     *
     * @param loginDto 登录对象
     * @param request  http请求
     * @param response http响应
     * @return
     */
    String login(LoginDto loginDto, HttpServletRequest request, HttpServletResponse response);

}
