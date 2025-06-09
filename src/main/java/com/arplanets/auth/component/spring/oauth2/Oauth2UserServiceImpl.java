package com.arplanets.auth.component.spring.oauth2;

import com.arplanets.auth.component.spring.oidc.OidcUserImpl;
import com.arplanets.auth.model.po.domain.User;
import com.arplanets.auth.service.persistence.UserInfoService;
import com.arplanets.auth.service.persistence.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

/**
 * 透過 IDP 的 User 資訊
 * 建立或查詢 Proxy 的 User
 * 建立或更新 User Claims
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class Oauth2UserServiceImpl implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final OidcUserService delegate = new OidcUserService();
    private final UserService userService;
    private final UserInfoService userInfoService;

    @Override
    @Transactional
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {

        // 取得原始的 IDP User 資訊
        OidcUser oidcUser = delegate.loadUser(userRequest);

        // 取得 Registration ID
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        log.debug("Processing user for registrationId={}", registrationId);
        if (registrationId == null || registrationId.isBlank()) {
            log.error("Authentication failed: Registration ID is null or blank.");
            throw new OAuth2AuthenticationException("Authentication failed: Registration ID is missing.");
        }

        // 取得原始 IdP 的 Subject ('sub' claim)
        String idpSub = oidcUser.getSubject();
        if (idpSub == null || idpSub.isBlank()) {
            log.error("Authentication failed: 'sub' claim from IdP is null or blank for registrationId: '{}'", registrationId);
            throw new OAuth2AuthenticationException("Authentication failed: OIDC user subject (sub) is missing from IdP.");
        }

        try {
            // 創建或查詢本地使用者 (使用 providerName 和 idpSub)
            User localUser = userService.findOrCreateUser(registrationId, idpSub);

            // 獲取並持久化 IdP 的 user info claims
            Map<String, Object> idpUserInfoClaims = oidcUser.getClaims();
            userInfoService.saveUserClaims(localUser.getUserId(), registrationId, idpUserInfoClaims);

            // 返回 Wrapper 物件
            // 將原始的 oidcUser 和 你組合好的 customPrincipalName 傳入 Wrapper
            // 這個 Wrapper 的 getName() 會回傳 customPrincipalName
            return new OidcUserImpl(oidcUser, localUser.getUserId());
        } catch (Exception e) {
            log.error("An error occurred during user creation, retrieval, or claim persistence: {}", e.getMessage(), e);
            throw new OAuth2AuthenticationException("Failed to process user data during authentication.");
        }
    }
}

