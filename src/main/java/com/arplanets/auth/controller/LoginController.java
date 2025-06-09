package com.arplanets.auth.controller;

import com.arplanets.auth.repository.persistence.ClientRegistrationMappingRepository;
import com.arplanets.auth.utils.StringUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Controller
@RequiredArgsConstructor
@Slf4j
public class LoginController {

    private final RequestCache requestCache = new HttpSessionRequestCache();
    private final ClientRegistrationMappingRepository clientRegistrationMappingRepository;

    private static final String AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization";
    private static final String LOGIN = "login";

    @GetMapping("/login")
    public String login(HttpServletRequest request, HttpServletResponse response, Model model) {

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

        // 4. 使用有效的 client_id 查詢對應的 IDP
        List<ClientRegistration> clientRegistrations;
        try {
            clientRegistrations = clientRegistrationMappingRepository.findByClientId(clientId);
        } catch (Exception e) {
            log.error("查詢 client_id '{}' 的 ClientRegistration 時發生錯誤", clientId, e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "讀取身份提供者選項時發生內部錯誤", e);
        }

        // 5. 檢查是否找到了對應的 IdP
        if (clientRegistrations == null || clientRegistrations.isEmpty()) {
            log.error("找不到 client_id '{}' 對應的 IDP", clientId);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "此應用程式目前沒有配置可用的登入選項 (身份提供者)。");
        }

        // 6. 返回登入頁面
        log.info("Retrieved Client Registration");
        model.addAttribute("registrations", clientRegistrations);
        model.addAttribute("authorizationBaseUri", AUTHORIZATION_REQUEST_BASE_URI);

        return LOGIN;

    }

}