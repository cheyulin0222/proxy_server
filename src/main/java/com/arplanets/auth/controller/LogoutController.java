package com.arplanets.auth.controller;

import com.arplanets.auth.model.LogoutRequestAttributes;
import com.arplanets.auth.repository.inmemory.LogoutStateRepository;
import com.arplanets.auth.utils.StringUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;

/**
 * 處理 Provider 登出後，導轉回 Client 指定頁面
 */
@Controller
@RequiredArgsConstructor
@Slf4j
public class LogoutController {

    private final LogoutStateRepository logoutStateRepository;
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @GetMapping("/logout/callback")
    public void logout(
            @RequestParam @NotBlank String state,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        String redirectUri;
        LogoutRequestAttributes attributes = logoutStateRepository.removeLogoutState(state);

        if (attributes != null) {
            redirectUri = attributes.getClientFinalRedirectUri();
        } else {
            // state 無效、已被使用或已過期
            log.error("Warning: Invalid, used, or expired state received in provider logout callback. State: {}", state);
            redirectStrategy.sendRedirect(request, response, StringUtil.ERROR_PATH);
            return;
        }

        // 重定向到原始 Client 的 URL
        if (StringUtils.hasText(redirectUri)) {
            redirectStrategy.sendRedirect(request, response, redirectUri);
            log.info("Redirecting to Client's post logout redirect uri successfully.");
        } else {
            log.error("Error: Final redirect URI is null after valid state retrieval. State: {}", state);
            redirectStrategy.sendRedirect(request, response, StringUtil.ERROR_PATH);
        }
    }
}
