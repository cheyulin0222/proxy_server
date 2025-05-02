package com.arplanets.auth.repository.impl;


import com.arplanets.auth.utils.JsonUtil;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@RequiredArgsConstructor
@Repository
public class ClientRegistrationRepositoryImpl implements ClientRegistrationRepository {

    private final JdbcTemplate jdbcTemplate;
    private final Map<String, Map<String, Object>> registrations = new ConcurrentHashMap<>();

    @PostConstruct
    public void load() {
        log.info("Load ClientRegistrations...");
        List<Map<String, Object>> allRegistrations = findAll();
        this.registrations.clear();
        allRegistrations.forEach(this::save);
    }

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        Map<String, Object> registrationData = this.registrations.get(registrationId);
        if (registrationData != null) {
            log.info("Retrieved ClientRegistration");
            return createClientRegistration(registrationData);
        }
        log.warn("Failed to Retrieve ClientRegistration");
        return null;
    }

    public String findUserPoolIdByRegistrationId(String registrationId) {
        Map<String, Object> registrationData = this.registrations.get(registrationId);
        if (registrationData != null) {
            log.info("Retrieved User Pool ID from ClientRegistrationRepository");
            return (String) registrationData.get("user_pool_id");
        }
        log.warn("Failed to Retrieve User Pool ID from ClientRegistrationRepository");
        return null;
    }

    public void save(Map<String, Object> clientRegistration) {
        this.registrations.put((String) clientRegistration.get("registration_id"), clientRegistration);
        log.info("已從資料庫載入 registrationId: {}", clientRegistration.get("registration_id"));
    }

    public void delete(String registrationId) {
        this.registrations.remove(registrationId);
        log.info("已從記憶體和資料庫刪除 registrationId: {}", registrationId);
    }

    private ClientRegistration createClientRegistration(Map<String, Object> data) {
        ClientRegistration.Builder builder = ClientRegistration
                .withRegistrationId((String) data.get("registration_id"))
                .clientId((String) data.get("client_id"))
                .clientSecret((String) data.get("client_secret"))
                .clientAuthenticationMethod(new ClientAuthenticationMethod((String) data.get("client_authentication_method")))
                .authorizationGrantType(new AuthorizationGrantType((String) data.get("authorization_grant_type")))
                .redirectUri((String) data.get("redirect_uri"))
                .clientName((String) data.get("provider_name"))
                .authorizationUri((String) data.get("authorization_uri"))
                .tokenUri((String) data.get("token_uri"))
                .userInfoUri((String) data.get("user_info_uri"))
                .jwkSetUri((String) data.get("jwk_set_uri"))
                .userNameAttributeName((String) data.get("user_name_attribute_name"));

        String scopesJson = (String) data.get("scopes");
        if (scopesJson != null) {
            try {
                Set<String> scopes = JsonUtil.convertJsonStringToSet(scopesJson, String.class);
                builder.scope(scopes);
            } catch (Exception e) {
                log.warn("ClientRegistration 解析 scopes JSON 失敗: registration_id = {}, scope = {}, ", data.get("registration_id"), scopesJson);
            }
        }
        return builder.build();
    }

    private List<Map<String, Object>> findAll() {
        String sql = "SELECT " +
                "registration_id, " +
                "user_pool_id, " +
                "provider_name, " +
                "client_id, " +
                "client_secret, " +
                "client_authentication_method, " +
                "authorization_grant_type, " +
                "redirect_uri, " +
                "authorization_uri, " +
                "token_uri, " +
                "user_info_uri, " +
                "jwk_set_uri, " +
                "user_name_attribute_name " +
                "FROM client_registration " +
                "WHERE is_active = 1 " +
                "AND deleted_at IS NULL";

        return jdbcTemplate.queryForList(sql);
    }

}
