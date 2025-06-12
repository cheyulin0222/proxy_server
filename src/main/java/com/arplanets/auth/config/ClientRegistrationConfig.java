package com.arplanets.auth.config;

import com.arplanets.auth.repository.persistence.ClientRegistrationPersistentRepository;
import com.arplanets.auth.service.inmemory.InMemoryClientRegistrationService;
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
    private final InMemoryClientRegistrationService inMemoryClientRegistrationService;

    @PostConstruct
    public void load() {
        log.info("Starting to load ClientRegistrations...");

        try {
            // 查詢所有 Client Registrations
            List<Map<String, Object>> allRegistrations = clientRegistrationPersistentRepository.findAll();
            if (allRegistrations == null || allRegistrations.isEmpty()) {
                log.error("No client registrations found in the database.");
                throw new RuntimeException("No client registrations found in the database.");
            }

            log.info("ClientRegistration.size={}", allRegistrations.size());

            // 註冊到應用程式
            allRegistrations.forEach(inMemoryClientRegistrationService::register);

            log.info("Successfully loaded {} client registrations.", allRegistrations.size());
        } catch (Exception e) {
            log.error("Failed to load client registration: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to load client registrations");
        }
    }
}
