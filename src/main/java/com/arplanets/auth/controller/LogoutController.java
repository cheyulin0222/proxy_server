package com.arplanets.auth.controller;

import com.arplanets.auth.model.LogoutRequestAttributes;
import com.arplanets.auth.repository.inmemory.LogoutStateRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;

@Controller
@RequiredArgsConstructor
public class LogoutController {

    private final LogoutStateRepository logoutStateRepository;
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @GetMapping("/logout/callback")
    public void logout(
            @RequestParam(name = "state", required = false) String state,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        String redirectUri;
        LogoutRequestAttributes attributes = null;

        if (StringUtils.hasText(state)) {
            attributes = logoutStateRepository.removeLogoutState(state);
        }

        if (attributes != null) {
            redirectUri = attributes.getClientFinalRedirectUri();
        } else {
            // state 無效、已被使用或已過期
            System.err.println("Warning: Invalid, used, or expired state received in upstream logout callback. State: " + state);
            // 如果狀態無效，重定向到一個安全的默認頁面
            redirectStrategy.sendRedirect(request, response, "/logout-fallback"); // 導向錯誤頁面
            return;
        }

        // 重定向到原始 Client 的 URL
        if (StringUtils.hasText(redirectUri)) {
            redirectStrategy.sendRedirect(request, response, redirectUri);
        } else {
            // 這種情況理論上不應該發生，除非 clientFinalRedirectUri 為空，但之前應該檢查過了
            System.err.println("Error: Final redirect URI is null after valid state retrieval. State: " + state);
            redirectStrategy.sendRedirect(request, response, "/logout-fallback");
        }
    }
}
