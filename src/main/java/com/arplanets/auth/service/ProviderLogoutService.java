package com.arplanets.auth.service;

import com.arplanets.auth.utils.StringUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Service
@RequiredArgsConstructor
@Slf4j
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
        Assert.notNull(request, "HttpServletRequest cannot be empty");
        Assert.notNull(response, "HttpServletResponse cannot be null");

        // 構建重定向到上游 OIDC Provider 的 URL
        String redirectUri = UriComponentsBuilder.fromUriString(endSessionEndpoint)
                .queryParam(StringUtil.ID_TOKEN_HINT_PARAM_NAME, upstreamIdTokenHint)
                .queryParam(StringUtil.POST_LOGOUT_REDIRECT_URI_PARAM_NAME, upstreamPostLogoutRedirectUri)
                .build()
                .toUriString();

        // 執行重定向
        this.redirectStrategy.sendRedirect(request, response, redirectUri);

        log.info("Redirect to Provider's end session endpoint successfully.");
    }
}
