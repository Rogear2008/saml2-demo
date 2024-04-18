package com.rogear.saml2.demo.common.dto;

import java.io.Serializable;

/**
 * @author Rogear2008
 * @since 4/18/24
 */
public class LoginDto implements Serializable {

    private static final long serialVersionUID = 96480849553237034L;

    /**
     * ???
     */
    private String username;

    /**
     * ??
     */
    private String password;

    /**
     * RelayState
     */
    private String relayState;

    public LoginDto() {
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getRelayState() {
        return relayState;
    }

    public void setRelayState(String relayState) {
        this.relayState = relayState;
    }
}
