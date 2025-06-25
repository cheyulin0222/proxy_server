package com.arplanets.auth.service;

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
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class ProviderLogoutService {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    public void initiateLogout(
            String endSessionEndpoint,
            Map<String, String> logoutParams,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        // 參數驗證，確保必要的參數不為空
        Assert.hasText(endSessionEndpoint, "endSessionEndpoint cannot be empty");
        Assert.notNull(logoutParams, "logoutParams cannot be null");
        Assert.notNull(request, "HttpServletRequest cannot be empty");
        Assert.notNull(response, "HttpServletResponse cannot be null");

        // 構建重定向到上游 OIDC Provider 的 URL
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(endSessionEndpoint);

        logoutParams.forEach((key, value) -> {
            Assert.hasText(value, "Logout parameter '" + key + "' cannot be empty.");
            builder.queryParam(key, value);
        });

        String redirectUri = builder.build().toUriString();

        // 執行重定向
        this.redirectStrategy.sendRedirect(request, response, redirectUri);

        log.info("Redirect to Provider's end session endpoint successfully.");
    }
}
