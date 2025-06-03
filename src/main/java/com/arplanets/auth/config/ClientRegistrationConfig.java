package com.arplanets.auth.config;

import com.arplanets.auth.repository.ClientRegistrationPersistentRepository;
import com.arplanets.auth.service.impl.ClientRegistrationService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.Map;

/**
 * 從資料庫載入各個 ClientRegistration
 */
@Configuration
@RequiredArgsConstructor
@Slf4j
public class ClientRegistrationConfig {

    private final ClientRegistrationPersistentRepository clientRegistrationPersistentRepository;
    private final ClientRegistrationService clientRegistrationService;

    @PostConstruct
    public void load() {
        log.info("Load ClientRegistrations...");
        List<Map<String, Object>> allRegistrations = clientRegistrationPersistentRepository.findAll();
        allRegistrations.forEach(registrationData -> {
            try {
                clientRegistrationService.register(registrationData);
            } catch (Exception e) {
                log.error("Failed to save client registration: {}", e.getMessage(), e);
                throw new RuntimeException("Failed to load client registrations", e);
            }
        });
    }
}
