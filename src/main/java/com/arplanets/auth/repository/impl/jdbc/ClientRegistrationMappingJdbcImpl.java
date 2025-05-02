package com.arplanets.auth.repository.impl.jdbc;

import com.arplanets.auth.model.po.domain.ClientRegistrationMapping;
import com.arplanets.auth.repository.ClientRegistrationMappingRepository;
import com.arplanets.auth.test.CustomClientRegistrationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;

@Repository
@RequiredArgsConstructor
public class ClientRegistrationMappingJdbcImpl implements ClientRegistrationMappingRepository {

    private final JdbcTemplate jdbcTemplate;

    @Override
    public void save(ClientRegistrationMapping clientRegistrationMapping) {
        String sql = "INSERT IGNORE INTO client_registration_mapping (client_id, registration_id) " +
                "VALUES (?, ?)";

        jdbcTemplate.update(sql, clientRegistrationMapping.getClientId(), clientRegistrationMapping.getRegistrationId());
    }

    @Override
    public void saveAll(List<ClientRegistrationMapping> clientRegistrationMappings) {
        List<Object[]> batchArgs = new ArrayList<>();
        clientRegistrationMappings.forEach(mapping -> batchArgs.add(new Object[]{
                mapping.getClientId(),
                mapping.getRegistrationId(),
        }));

        String sql = "INSERT IGNORE INTO client_registration_mapping (client_id, registration_id) " +
                "VALUES (?, ?)";

        jdbcTemplate.batchUpdate(sql, batchArgs);
    }

    @Override
    public List<ClientRegistration> findByClientId(String clientId) {
        String sql = "SELECT " +
                "cr.registration_id, " +
                "cr.provider_name, " +
                "cr.client_id, " +
                "cr.client_secret, " +
                "cr.client_authentication_method, " +
                "cr.authorization_grant_type, " +
                "cr.redirect_uri, " +
                "cr.authorization_uri, " +
                "cr.token_uri, " +
                "cr.user_info_uri, " +
                "cr.jwk_set_uri, " +
                "cr.user_name_attribute_name, " +
                "cr.scopes " +
                "FROM client_registration_mapping crm " +
                "INNER JOIN client_registration cr ON cr.registration_id = crm.registration_id " +
                "INNER JOIN oauth2_registered_client orc ON crm.client_id = orc.client_id " +
                "INNER JOIN user_pool up ON up.user_pool_id = orc.user_pool_id " +
                "WHERE crm.client_id = ? " +
                "AND up.is_active = 1 " +
                "AND up.deleted_at IS NULL " +
                "AND cr.is_active = 1 " +
                "AND cr.deleted_at IS NULL " +
                "AND orc.is_active = 1 " +
                "AND orc.deleted_at IS NULL " +
                "AND cr.user_pool_id = orc.user_pool_id";

        return jdbcTemplate.query(sql, new CustomClientRegistrationRepository.ClientRegistrationRowMapper(), clientId);

    }
}
