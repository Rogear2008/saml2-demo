package com.rogear.saml2.demo.sp.service;

import com.rogear.saml2.demo.common.dto.LoginDto;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Rogear2008
 * @since 4/18/24
 */
public interface SpService {

    /**
     * 进入主页
     *
     * @param request  请求
     * @param response 响应
     * @return 跳转地址
     */
    String index(HttpServletRequest request, HttpServletResponse response);

    /**
     * 登出
     *
     * @param request 请求
     * @return 跳转地址
     */
    String logout(HttpServletRequest request, HttpServletResponse response);

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
