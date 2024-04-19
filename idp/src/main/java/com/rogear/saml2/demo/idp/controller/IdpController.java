package com.rogear.saml2.demo.idp.controller;

import com.rogear.saml2.demo.common.dto.LoginDto;
import com.rogear.saml2.demo.idp.service.IdpService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.thymeleaf.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static com.rogear.saml2.demo.common.Constants.LOGIN_USERNAME;
import static com.rogear.saml2.demo.common.Constants.RELAY_STATE;
/**
 * @author Rogear2008
 * @since 4/18/24
 */
@Controller
@RequestMapping("/idp")
public class IdpController {

    @Autowired
    private IdpService idpService;

    /**
     * 打开登录页
     *
     * @param RelayState relayState
     * @param model      模型
     * @return 登录页
     */
    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String login(String RelayState, Model model) {
        model.addAttribute(RELAY_STATE, RelayState);
        return "login";
    }

    /**
     * 登录
     *
     * @param loginDto 登录对象
     * @param request  请求
     * @param response 响应
     * @return 跳转地址
     */
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public String login(LoginDto loginDto, HttpServletRequest request, HttpServletResponse response) {
        return idpService.login(loginDto, request, response);
    }

    /**
     * 主页
     *
     * @param model   模型
     * @param request 请求
     * @return 跳转地址
     */
    @RequestMapping(value = "/index", method = RequestMethod.GET)
    public String index(Model model, HttpServletRequest request) {
        String loginUsername = (String) request.getSession().getAttribute(LOGIN_USERNAME);
        if (StringUtils.isEmpty(loginUsername)) {
            return "login";
        }
        model.addAttribute(LOGIN_USERNAME, loginUsername);
        return "index";
    }
}
