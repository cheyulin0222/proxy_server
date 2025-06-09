package com.arplanets.auth.repository.persistence;

import com.arplanets.auth.model.po.domain.ClientRegistrationMapping;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

import java.util.List;

public interface ClientRegistrationMappingRepository {

    void save(ClientRegistrationMapping clientRegistrationMapping);
    void saveAll(List<ClientRegistrationMapping> clientRegistrationMappings);
    List<ClientRegistration> findByClientId(String clientId);
}
