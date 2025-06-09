package com.arplanets.auth.service.inmemory;

import com.arplanets.auth.repository.inmemory.InMemoryClientRegistrationRepository;
import com.arplanets.auth.model.ClientRegistrationContext;
import com.arplanets.auth.utils.JsonUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class InMemoryClientRegistrationService {

    private final InMemoryClientRegistrationRepository inMemoryClientRegistrationRepository;

    public ClientRegistrationContext get(String registrationId) {
        return inMemoryClientRegistrationRepository.get(registrationId);
    }

    public void register(String userPoolId, ClientRegistration clientRegistration) {
        inMemoryClientRegistrationRepository.register(userPoolId, clientRegistration);
    }

    public void register(Map<String, Object> data) {
        ClientRegistration clientRegistration = createClientRegistration(data);
        String userPoolId = (String) data.get("user_pool_id");
        register(userPoolId, clientRegistration);
    }

    public void remove(String registrationId) {
        inMemoryClientRegistrationRepository.remove(registrationId);
    }

    public void removeByUserPoolId(String userPoolId) {
        List<String> registrationIds = findRegistrationIdsByPoolId(userPoolId);
        registrationIds.forEach(this::remove);
    }

    public List<String> findRegistrationIdsByPoolId(String poolId) {
        return this.inMemoryClientRegistrationRepository.getAll().stream()
                .filter(clientRegistrationContext -> poolId.equals(clientRegistrationContext.getUserPoolId()))
                .map(clientRegistrationContext -> clientRegistrationContext.getClientRegistration().getRegistrationId())
                .toList();
    }

    public String findUserPoolIdByRegistrationId(String registrationId) {
        log.info("registrationId={}", registrationId);
        ClientRegistrationContext registrationContext = inMemoryClientRegistrationRepository.get(registrationId);
        log.info("registrationContext={}", registrationContext);
        if (registrationContext != null) {
            log.info("userPoolId={}", registrationContext.getUserPoolId());
        }

        if (registrationContext != null && StringUtils.hasText(registrationContext.getUserPoolId())) {
            log.info("Retrieved User Pool ID from ClientRegistrationRepository");
            return registrationContext.getUserPoolId();
        }
        log.warn("Failed to Retrieve User Pool ID from ClientRegistrationRepository");
        return null;
    }

    public ClientRegistration createClientRegistration(Map<String, Object> data) {
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
                .userNameAttributeName((String) data.get("user_name_attribute_name"))
                .providerConfigurationMetadata(Collections.singletonMap("end_session_endpoint", data.get("post_logout_redirect_uris")));

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
}
