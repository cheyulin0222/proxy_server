package com.arplanets.auth.service;

import com.arplanets.auth.model.CustomOidcUser;
import com.arplanets.auth.model.po.domain.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final OidcUserService delegate = new OidcUserService();
    private final UserService userService;
    private final UserInfoService userInfoService;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {

        OidcUser oidcUser = delegate.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        String providerName = userRequest.getClientRegistration().getClientName();

        // 3. 獲取 IdP 的 Subject ('sub' claim)
        String idpSub = oidcUser.getSubject();
        if (idpSub == null) {
            log.error("IdP 的 sub 為 null，無法組合 Principal Name。Provider: {}", providerName);
            throw new OAuth2AuthenticationException("OIDC user subject (sub) from IdP is null for registrationId: " + registrationId);
        }

        // *** 4. 組合你想要的 Principal Name 格式 ***
        String customPrincipalName = providerName + ":" + idpSub;

        try {
            // 5. 創建或查詢本地使用者 (使用 providerName 和 idpSub)
            User localUser = userService.findOrCreateUser(providerName, idpSub);

            // 6. 獲取並持久化 IdP 的 user info claims
            Map<String, Object> idpUserInfoClaims = oidcUser.getClaims();
            userInfoService.saveUserClaims(localUser.getUserId(), registrationId, idpUserInfoClaims);
        } catch (Exception e) {
            // 根據你的業務需求處理錯誤，例如紀錄 Log 或拋出特定例外
            log.error("處理本地用戶或保存 Claims 時發生錯誤: {}", e.getMessage(), e);
            // 考慮是否要因此中斷登入流程
            // throw new OAuth2AuthenticationException("Failed to process local user data.", e);
        }

        // *** 7. 返回 Wrapper 物件 ***
        // 將原始的 oidcUser 和 你組合好的 customPrincipalName 傳入 Wrapper
        // 這個 Wrapper 的 getName() 會回傳 customPrincipalName
        return new CustomOidcUser(oidcUser, customPrincipalName);
    }
}

