package com.arplanets.auth.component.spring.oidc;

import com.fasterxml.jackson.annotation.*;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

/**
 * 處理 OidcUserImpl 的序列化和反序列化過程
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(
        fieldVisibility = JsonAutoDetect.Visibility.ANY,
        getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE
)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class OidcUserImplWrapperMixin {

    @JsonProperty("customUserName")
    private String customUserName;

    @JsonProperty("oidcUser")
    private OidcUser oidcUser;

    @JsonCreator
    OidcUserImplWrapperMixin(
            @JsonProperty("oidcUser") OidcUser oidcUser,
            @JsonProperty("customUserName") String customUserName) {
    }
}
