package com.rogear.saml2.demo.sp.service.dto;

import java.io.Serializable;

/**
 * @author Rogear2008
 * @since 4/18/24
 */
public class SsoDto implements Serializable {
    private static final long serialVersionUID = 275267712174223177L;

    private String SAMLResponse;

    private String RelayState;

    public SsoDto() {
    }

    public String getSAMLResponse() {
        return SAMLResponse;
    }

    public void setSAMLResponse(String SAMLResponse) {
        this.SAMLResponse = SAMLResponse;
    }

    public String getRelayState() {
        return RelayState;
    }

    public void setRelayState(String relayState) {
        this.RelayState = relayState;
    }
}
