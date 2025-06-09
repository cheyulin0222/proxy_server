package com.arplanets.auth.component.spring.oauth2;


import com.arplanets.auth.model.ClientRegistrationContext;
import com.arplanets.auth.service.inmemory.InMemoryClientRegistrationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Component;

/**
 * Spring 用來選擇該使用哪個 Provider
 */
@Slf4j
@RequiredArgsConstructor
@Component
public class ClientRegistrationRepositoryImpl implements ClientRegistrationRepository {

    private final InMemoryClientRegistrationService inMemoryClientRegistrationService;

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        ClientRegistrationContext registrationContext = inMemoryClientRegistrationService.get(registrationId);

        if (registrationContext == null || registrationContext.getClientRegistration() == null) {
            log.warn("Failed to Retrieve ClientRegistration");
            return null;
        }

        return registrationContext.getClientRegistration();
    }

}
