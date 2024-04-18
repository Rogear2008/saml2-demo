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
     * ??
     *
     * @param loginDto ????
     * @param request  http??
     * @param response http??
     * @return
     */
    String login(LoginDto loginDto, HttpServletRequest request, HttpServletResponse response);

}
