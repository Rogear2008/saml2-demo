package com.rogear.saml2.demo.idp.service.impl;

import com.rogear.saml2.demo.common.dto.LoginDto;
import com.rogear.saml2.demo.idp.service.IdpSamlService;
import com.rogear.saml2.demo.idp.service.IdpService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import static com.rogear.saml2.demo.common.Constants.LOGIN_USERNAME;
import static com.rogear.saml2.demo.common.Constants.SSO_TO_SP;
/**
 * @author Rogear2008
 * @since 4/18/24
 */
@Service
public class IdpServiceImpl implements IdpService {

    private static final Logger log = LoggerFactory.getLogger(IdpServiceImpl.class);

    @Autowired
    private IdpSamlService idpSamlService;

    @Override
    public String login(LoginDto loginDto, HttpServletRequest request, HttpServletResponse httpServletResponse) {
        String username = loginDto.getUsername();
//        String password = loginDto.getPassword();
        // 验证用户名和密码，这里作为示例就不验证了，直接认为认证成功
        log.info("Login username: " + username);
        // 设置登录状态
        HttpSession session = request.getSession();
        session.setAttribute(LOGIN_USERNAME, username);

        // 根据标识判断进入主页还是调转sp
        if (session.getAttribute(SSO_TO_SP) == null) {
            return "redirect:/idp/index";
        } else {
            idpSamlService.ssoToSp(loginDto.getRelayState(), request, httpServletResponse);
            return null;
        }
    }
}
