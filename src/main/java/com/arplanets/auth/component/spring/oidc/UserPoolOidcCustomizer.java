package com.arplanets.auth.component.spring.oidc;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;
import java.util.function.Consumer;

@Slf4j
@Component
public class UserPoolOidcCustomizer implements Consumer<OidcProviderConfiguration.Builder> {

    private static final String VALIDATED_USER_POOL_ID_ATTR = "validatedUserPoolId";

    @Override
    public void accept(OidcProviderConfiguration.Builder builder) {

        String userPoolId = getUserPoolIdFromRequest();

        if (userPoolId == null) {
            // 如果到這裡 userPoolId 還是 null，說明 ValidationFilter 可能配置有誤或未執行
            // 或者請求根本不是通過預期的動態路徑來的（雖然 Matcher 應該阻止這種情況）
            log.error("Cannot determine User Pool ID in OidcProviderConfiguration customizer. Request may not have been validated.");
            // 在這裡可能需要決定是拋出異常還是返回一個錯誤的/空的配置，取決於你的策略
            // 為了安全，可能不應該繼續生成配置
            // 清空 builder 可能是一種方式，或者依賴後續 build() 的校驗
            // builder = OidcProviderConfiguration.builder(); // Re-init to clear? Needs testing.
            return; // 或者拋出異常
        }

        // 2. 獲取基礎配置 (Issuer 和 Settings)
        AuthorizationServerContext context = AuthorizationServerContextHolder.getContext();
        if (context == null) {
            log.error("AuthorizationServerContext is null in OidcProviderConfiguration customizer.");
            return; // 無法繼續
        }
        String baseIssuer = context.getIssuer();
        AuthorizationServerSettings serverSettings = context.getAuthorizationServerSettings();

        // 3. 構建動態 Issuer URL
        String dynamicIssuer = buildUrl(baseIssuer, userPoolId, null);

        // 4. **覆蓋** Builder 中的值
        log.debug("Customizing OIDC Provider Configuration for User Pool: {}", userPoolId);
        builder.issuer(dynamicIssuer); // 覆蓋 Issuer

        // 覆蓋所有端點 URL
        builder.authorizationEndpoint(buildUrl(dynamicIssuer, null, serverSettings.getAuthorizationEndpoint()));
        builder.tokenEndpoint(buildUrl(dynamicIssuer, null, serverSettings.getTokenEndpoint()));
        builder.jwkSetUrl(buildUrl(dynamicIssuer, null, serverSettings.getJwkSetEndpoint()));

        // 處理可選端點
        builder.userInfoEndpoint(buildUrl(dynamicIssuer, null, serverSettings.getOidcUserInfoEndpoint()));
        builder.deviceAuthorizationEndpoint(buildUrl(dynamicIssuer, null, serverSettings.getDeviceAuthorizationEndpoint()));
        builder.endSessionEndpoint(buildUrl(dynamicIssuer, null, serverSettings.getOidcLogoutEndpoint()));
        builder.tokenRevocationEndpoint(buildUrl(dynamicIssuer, null, serverSettings.getTokenRevocationEndpoint()));
        builder.tokenIntrospectionEndpoint(buildUrl(dynamicIssuer, null, serverSettings.getTokenIntrospectionEndpoint()));


        // 5. 設置/覆蓋 Supported 列表 (確保與你的實際能力和 Default 示例一致)
        // 你需要仔細核對這些列表是否符合你的伺服器實際支持情況
        builder.tokenEndpointAuthenticationMethods((methods) -> methods.add(
//                "client_secret_post",
//                "client_secret_jwt",
//                "private_key_jwt",
//                "tls_client_auth",
//                "self_signed_tls_client_auth",
                "client_secret_basic"
        ));
        builder.grantTypes((types) -> types.addAll(List.of(
//                AuthorizationGrantType.CLIENT_CREDENTIALS.getValue(),
//                AuthorizationGrantType.DEVICE_CODE.getValue(),
//                AuthorizationGrantType.TOKEN_EXCHANGE.getValue(),
                AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
                AuthorizationGrantType.REFRESH_TOKEN.getValue()
        )));
        // 假設撤銷和內省端點支持的認證方法與令牌端點相同
        builder.tokenRevocationEndpointAuthenticationMethods((methods) -> methods.addAll(List.of(
                "client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt"
                // Add "tls_client_auth", "self_signed_tls_client_auth" if supported
        )));
        builder.tokenIntrospectionEndpointAuthenticationMethods((methods) -> methods.addAll(List.of(
                "client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt"
                // Add "tls_client_auth", "self_signed_tls_client_auth" if supported
        )));


        builder.responseTypes((types) -> types.add(OAuth2AuthorizationResponseType.CODE.getValue()));
        builder.scopes((scopes) -> scopes.addAll(List.of("openid", "profile", "email")));
        builder.subjectTypes(types -> types.add("public"));
        builder.idTokenSigningAlgorithms(algorithms -> algorithms.add(SignatureAlgorithm.RS256.getName()));
        builder.codeChallengeMethods((methods)-> methods.add("S256"));


        // 6. 處理 tls_client_certificate_bound_access_tokens
        // 根據你的實際 mTLS 支持情況設置 true 或 false
        builder.claims((claims) -> claims.put("tls_client_certificate_bound_access_tokens", false));

    }

    @Nullable
    private String getUserPoolIdFromRequest() {
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes instanceof ServletRequestAttributes) {
            HttpServletRequest request = ((ServletRequestAttributes) requestAttributes).getRequest();
            // 從 request attribute 獲取經過驗證的 ID
            Object validatedId = request.getAttribute(VALIDATED_USER_POOL_ID_ATTR);
            if (validatedId instanceof String) {
                return (String) validatedId;
            } else {
                log.warn("Validated User Pool ID not found in request attribute '{}'", VALIDATED_USER_POOL_ID_ATTR);
                // Fallback: 嘗試從路徑再次解析（但不推薦，應該依賴 Filter）
                // Map<String, String> pathVariables = (Map<String, String>) request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
                // if (pathVariables != null) return pathVariables.get("userPoolId");
            }
        } else {
            log.warn("Cannot access ServletRequestAttributes from RequestContextHolder.");
        }
        return null;
    }

    private String buildUrl(String baseIssuer, String userPoolId, String relativePath) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(baseIssuer);
        if (userPoolId != null && !userPoolId.isBlank()) {
            builder.pathSegment(userPoolId);
        }
        if (relativePath != null && !relativePath.isBlank()) {
            builder.path(relativePath.startsWith("/") ? relativePath : "/" + relativePath);
        }

        return builder.build().toUriString();
    }
}
