package com.arplanets.auth.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class ProviderLogoutService {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    public void initiateLogout(
            String endSessionEndpoint,
            String upstreamIdTokenHint,
            String upstreamPostLogoutRedirectUri,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        // 參數驗證，確保必要的參數不為空
        Assert.hasText(endSessionEndpoint, "endSessionEndpoint cannot be empty");
        Assert.hasText(upstreamIdTokenHint, "upstreamIdTokenHint cannot be empty");
        Assert.hasText(upstreamPostLogoutRedirectUri, "upstreamPostLogoutRedirectUri cannot be empty");
        Assert.notNull(response, "HttpServletResponse cannot be null");

        // 構建重定向到上游 OIDC Provider 的 URL
        UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(endSessionEndpoint)
                .queryParam("id_token_hint", upstreamIdTokenHint)
                .queryParam("post_logout_redirect_uri", upstreamPostLogoutRedirectUri);

        // 如果需要，可以添加 'state' 參數到上游登出請求 (如果上游 Provider 需要，通常是為了防止 CSRF)
        // 這個 state 與我們自己內部用於追蹤 Client 回調的 state 是不同的，除非上游也用相同名字。
        // 但由於我們已經在 upstreamPostLogoutRedirectUri 中包含了我們的 state，這裡通常不需要再加一個。
        // 例如：.queryParam("state", "another_random_state_for_upstream_provider");

        String redirectUri = uriBuilder.build().toUriString();

        // 執行重定向
        // sendRedirect() 會設置 HTTP 狀態碼為 302 (或 303)，並在 Location 頭部設置重定向 URL
        this.redirectStrategy.sendRedirect(request, response, redirectUri);
    }
}
