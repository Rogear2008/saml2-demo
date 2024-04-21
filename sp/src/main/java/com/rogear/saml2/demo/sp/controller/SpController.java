package com.rogear.saml2.demo.sp.controller;

import com.rogear.saml2.demo.common.dto.LoginDto;
import com.rogear.saml2.demo.sp.service.SpService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Rogear2008
 * @since 4/18/24
 */
@Controller
@RequestMapping("/sp")
public class SpController {

    @Autowired
    private SpService spService;

    /**
     * 进入主页
     *
     * @param request  请求
     * @param response 响应
     * @return 跳转地址
     */
    @RequestMapping(value = "/index", method = RequestMethod.GET)
    public String index(HttpServletRequest request, HttpServletResponse response) {
        return spService.index(request, response);
    }

    /**
     * 打开登录页
     *
     * @return 跳转地址
     */
    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String login() {
        return "login";
    }

    /**
     * 登录
     *
     * @param loginDto 登录对象
     * @param request  http请求
     * @param response http响应
     * @return
     */
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public String login(LoginDto loginDto, HttpServletRequest request, HttpServletResponse response) {
        return spService.login(loginDto, request, response);
    }

    /**
     * 登出
     *
     * @param request 请求
     * @return 跳转地址
     */
    @RequestMapping(value = "logout", method = RequestMethod.GET)
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        return spService.logout(request, response);
    }
}
