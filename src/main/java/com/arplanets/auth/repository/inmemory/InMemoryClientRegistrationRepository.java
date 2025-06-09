package com.arplanets.auth.repository.inmemory;

import com.arplanets.auth.model.ClientRegistrationContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * InMemory ClientRegistration Repository
 */
@Component
@Slf4j
public class InMemoryClientRegistrationRepository {

    private final Map<String, ClientRegistrationContext> registrations = new ConcurrentHashMap<>();

    public void register(String userPoolId, ClientRegistration clientRegistration) {
        validate(clientRegistration);
        validateField(userPoolId, "user_pool_id");

        ClientRegistrationContext clientRegistrationContext = new ClientRegistrationContext(clientRegistration, userPoolId);
        registrations.put(clientRegistration.getRegistrationId(), clientRegistrationContext);

        log.info("Registered ClientRegistration with ID '{}' for User Pool ID '{}'. Client details: {}.",
                clientRegistration.getRegistrationId(),
                userPoolId,
                clientRegistration);
    }

    public ClientRegistrationContext get(String registrationId) {
        return this.registrations.get(registrationId);
    }

    public List<ClientRegistrationContext> getAll() {
        return new ArrayList<>(registrations.values());
    }

    public void remove(String registrationId) {
        this.registrations.remove(registrationId);
        log.info("Removed ClientRegistration for registrationId: {}", registrationId);
    }

    private void validate(ClientRegistration clientRegistration) {
        if (clientRegistration == null) {
            log.error("clientRegistrationData 不能為空");
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
        validateField((String) clientRegistration.getProviderDetails().getConfigurationMetadata().get("end_session_endpoint"), "end_session_endpoint");
        validateField(clientRegistration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName(), "user_name_attribute_name");
        validateField(String.join(",", clientRegistration.getScopes()), "scopes");
    }

    private void validateField(String value, String fieldName) {
        if (!StringUtils.hasText(value)) {
            log.error("{} 不能為空", fieldName);
            throw new IllegalArgumentException(fieldName + " 不能為空");
        }
    }
}
