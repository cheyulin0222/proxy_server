package com.arplanets.auth.repository.impl.jdbc;


import com.arplanets.auth.model.ClientRegistrationContext;
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
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@RequiredArgsConstructor
@Repository
public class ClientRegistrationRepositoryJdbcImpl implements ClientRegistrationRepository {

    private final JdbcTemplate jdbcTemplate;
    private final Map<String, ClientRegistrationContext> registrations = new ConcurrentHashMap<>();

    @PostConstruct
    public void load() {
        log.info("Load ClientRegistrations...");
        List<Map<String, Object>> allRegistrations = findAll();
        this.registrations.clear();
        allRegistrations.forEach(registrationData -> {
            try {
                this.save(registrationData);
            } catch (Exception e) {
                log.error("Failed to save client registration: {}", e.getMessage(), e);
                throw new RuntimeException("Failed to load client registrations", e);
            }
        });
    }

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        ClientRegistrationContext registrationContext = this.registrations.get(registrationId);
        if (registrationContext != null && registrationContext.getClientRegistration() != null) {
            log.info("Retrieved ClientRegistration");
            return registrationContext.getClientRegistration();
        }
        log.warn("Failed to Retrieve ClientRegistration");
        return null;
    }

    public String findUserPoolIdByRegistrationId(String registrationId) {
        ClientRegistrationContext registrationContext = this.registrations.get(registrationId);
        if (registrationContext != null && StringUtils.hasText(registrationContext.getUserPoolId())) {
            log.info("Retrieved User Pool ID from ClientRegistrationRepository");
            return registrationContext.getUserPoolId();
        }
        log.warn("Failed to Retrieve User Pool ID from ClientRegistrationRepository");
        return null;
    }

    public void save(Map<String, Object> clientRegistrationData) throws Exception {

        try {

            ClientRegistration clientRegistration = createClientRegistration(clientRegistrationData);
            validate(clientRegistration);
            String userPoolId = (String) clientRegistrationData.get("user_pool_id");
            validateField(userPoolId, "user_pool_id");

            ClientRegistrationContext clientRegistrationContext = new ClientRegistrationContext(clientRegistration, userPoolId);

            this.registrations.put(clientRegistration.getRegistrationId(), clientRegistrationContext);
        } catch (Exception e) {
            throw new Exception(e);
        }
    }

    public void delete(String registrationId) {
        this.registrations.remove(registrationId);
        log.info("已從記憶體和資料庫刪除 registrationId: {}", registrationId);
    }

    private void validate(ClientRegistration clientRegistration) {
        if (clientRegistration == null) {
            throw new IllegalArgumentException("clientRegistrationData 不能為空");
        }

        validateField(clientRegistration.getRegistrationId(), "registration_id");
        validateField(clientRegistration.getClientId(), "client_id");
        validateField(clientRegistration.getClientSecret(), "client_secret");
        validateField(clientRegistration.getClientAuthenticationMethod().getValue(), "client_authentication_method");
        validateField(clientRegistration.getAuthorizationGrantType().getValue(), "authorization_grant_type");
        validateField(clientRegistration.getRedirectUri(), "redirect_uri");
        validateField(clientRegistration.getClientName(), "provider_name");
        validateField(clientRegistration.getProviderDetails().getAuthorizationUri(), "authorization_uri");
        validateField(clientRegistration.getProviderDetails().getTokenUri(), "token_uri");
        validateField(clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri(), "user_info_uri");
        validateField(clientRegistration.getProviderDetails().getJwkSetUri(), "jwk_set_uri");
        validateField(clientRegistration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName(), "user_name_attribute_name");
        validateField(String.join(",", clientRegistration.getScopes()), "scopes");
    }

    private void validateField(String value, String fieldName) {
        if (!StringUtils.hasText(value)) {
            log.error("{} 不能為空", fieldName);
            throw new IllegalArgumentException(fieldName + " 不能為空");
        }
        if (!"client_secret".equals(fieldName)) {
            log.info("{}: {}", fieldName, value);
        }
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
                "user_name_attribute_name, " +
                "scopes " +
                "FROM client_registration " +
                "WHERE is_active = 1 " +
                "AND deleted_at IS NULL";

        return jdbcTemplate.queryForList(sql);
    }

}
