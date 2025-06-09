package com.arplanets.auth.component.spring.oidc;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;
import java.util.Map;

/**
 * 讓 Spring 能夠在用戶授權時，用 Arplanet 的 User_id 來做紀錄
 */
@Slf4j
public class OidcUserImpl implements OidcUser, Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private final OidcUser oidcUser;
    private final String customUserName;

    @JsonCreator
    public OidcUserImpl(
            @JsonProperty("oidcUser") OidcUser oidcUser,
            @JsonProperty("customUserName") String customUserName) {
        this.oidcUser = oidcUser;
        this.customUserName = customUserName;
    }


    @Override
    @JsonIgnore
    public Map<String, Object> getClaims() {
        return oidcUser != null ? oidcUser.getClaims() : null;
    }

    @Override
    @JsonIgnore
    public OidcUserInfo getUserInfo() {
        return oidcUser != null ? oidcUser.getUserInfo() : null;
    }

    @Override
    @JsonIgnore
    public OidcIdToken getIdToken() {
        return oidcUser != null ? oidcUser.getIdToken() : null;
    }

    @Override
    @JsonIgnore
    public Map<String, Object> getAttributes() {
        return oidcUser != null ? oidcUser.getAttributes() : null;
    }

    @Override
    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return oidcUser != null ? oidcUser.getAuthorities() : null;
    }

    @Override
    public String getName() {
        return this.customUserName;
    }
}
