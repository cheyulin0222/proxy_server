package com.arplanets.auth.filter;

import com.arplanets.auth.repository.RegisteredClientPersistentRepository;
import com.arplanets.auth.service.impl.ClientRegistrationService;
import com.arplanets.auth.utils.StringUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
public class RegistrationIdValidationFilter extends OncePerRequestFilter {

    private final RequestCache requestCache = new HttpSessionRequestCache();
    private final ClientRegistrationService clientRegistrationService;
    private final RegisteredClientPersistentRepository registeredClientPersistentRepository;
    private static final RequestMatcher OAUTH2_AUTH_REQUEST_MATCHER =
            new AntPathRequestMatcher("/oauth2/authorization/{registrationId}");

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {

        String clientId = null;
        String[] clientIdValues = null;

        // 1. 嘗試獲取 SavedRequest
        SavedRequest savedRequest = requestCache.getRequest(request, response);

        // 2. 嘗試提取 client_id
        if (savedRequest != null) {
            clientIdValues = savedRequest.getParameterValues(StringUtil.CLIENT_ID_ATTRIBUTE_NAME);
            if (clientIdValues != null) {
                Optional<String> option = Arrays.stream(clientIdValues).findFirst();
                if (option.isPresent()) {
                    clientId = option.get();
                }
            }
        }

        // 3. 檢查是否是有效的 client_id
        if (!StringUtils.hasText(clientId) || clientIdValues.length != 1) {
            log.error("無法確定有效的 client_id。");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "無法識別客戶端應用程式 (缺少或無效的 client_id)。");
        }

        String registrationId = extractRegistrationId(request);

        if (registrationId == null) {
            log.warn("在 SecurityFilterChain 中無法從路徑 {} 提取 registrationId。", request.getRequestURI());
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "無法識別的授權請求路徑");
            return;
        }

        // 獲取 userPoolIdFromRegistrationId
        String userPoolIdFromRegistrationId = clientRegistrationService.findUserPoolIdByRegistrationId(registrationId);
        // 獲取 userPoolIdFromClientId
        String userPoolIdFromClientId = registeredClientPersistentRepository.findUserPoolIdByClientId(clientId);

        log.info("userPoolIdFromRegistrationId={}", userPoolIdFromRegistrationId);
        log.info("userPoolIdFromClientId={}", userPoolIdFromClientId);

        // 進行比較 (只有兩者都成功獲取時才比較)
        if (userPoolIdFromRegistrationId != null && userPoolIdFromClientId != null &&
                !userPoolIdFromRegistrationId.equals(userPoolIdFromClientId)) {
            log.error("UserPool ID 不匹配。RegistrationId ({}) 的 UserPool ID: {}, ClientId ({}) 的 UserPool ID: {}",
                    registrationId, userPoolIdFromRegistrationId, clientId, userPoolIdFromClientId);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "UserPool ID 不匹配。");
        } else if (userPoolIdFromRegistrationId == null || userPoolIdFromClientId == null) {
            log.warn("未能同時獲取 Registration ID 和 Client ID 的 UserPool ID，跳過匹配檢查。");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "UserPool ID 為 null。");
        }

        filterChain.doFilter(request, response);
    }

    private String extractRegistrationId(HttpServletRequest request) {
        RequestMatcher.MatchResult matchResult = OAUTH2_AUTH_REQUEST_MATCHER.matcher(request);

        // 2. 檢查是否匹配
        if (matchResult.isMatch()) {
            Map<String, String> variables = matchResult.getVariables();
            return variables.get("registrationId");
        } else {
            log.warn("Request URI '{}' did not match '{}' in extractRegistrationId, although shouldNotFilter passed. This indicates an inconsistency.",
                    request.getRequestURI(), OAUTH2_AUTH_REQUEST_MATCHER);
            return null;
        }
    }

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        return !OAUTH2_AUTH_REQUEST_MATCHER.matches(request);
    }
}
