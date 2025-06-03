package com.arplanets.auth.component.spring.oauth2;


import com.arplanets.auth.model.ClientRegistrationContext;
import com.arplanets.auth.service.impl.ClientRegistrationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Component;


@Slf4j
@RequiredArgsConstructor
@Component
public class ClientRegistrationRepositoryImpl implements ClientRegistrationRepository {

    private final ClientRegistrationService clientRegistrationService;

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        ClientRegistrationContext registrationContext = clientRegistrationService.get(registrationId);
        if (registrationContext != null && registrationContext.getClientRegistration() != null) {
            return registrationContext.getClientRegistration();
        }
        log.warn("Failed to Retrieve ClientRegistration");
        return null;
    }

}
