package com.rogear.saml2.demo.sp.service.impl;

import com.rogear.saml2.demo.common.dto.LoginDto;
import com.rogear.saml2.demo.sp.service.SpSamlService;
import com.rogear.saml2.demo.sp.service.SpService;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import static com.rogear.saml2.demo.common.Constants.LOGIN_USERNAME;

/**
 * @author Rogear2008
 * @since 4/18/24
 */
@Service
public class SpServiceImpl implements SpService {

    private static final Logger log = LoggerFactory.getLogger(SpServiceImpl.class);

    @Autowired
    private SpSamlService spSamlService;

    @Override
    public String index(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession();
        if (StringUtils.isEmpty((String) session.getAttribute(LOGIN_USERNAME))) {
            log.info("Have not login, goto idp sso");

            spSamlService.ssoToIdp(response);
        }
        return "index";
    }

    @Override
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession();
        String username = (String) session.getAttribute(LOGIN_USERNAME);
        //?????????
        if (StringUtils.isEmpty(username)) {
            return "redirect:/sp/login";
        }
        spSamlService.sloToIdp(username, response);
        return null;
    }

    @Override
    public String login(LoginDto loginDto, HttpServletRequest request, HttpServletResponse response) {
        String username = loginDto.getUsername();
//        String password = loginDto.getPassword();
        // ?????????????????????????????
        log.info("Login username: " + username);
        // ??????
        HttpSession session = request.getSession();
        session.setAttribute(LOGIN_USERNAME, username);
        // ????
        return "redirect:/sp/index";
    }

}
