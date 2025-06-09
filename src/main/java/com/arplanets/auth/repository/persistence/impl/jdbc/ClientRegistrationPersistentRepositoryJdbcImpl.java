package com.arplanets.auth.repository.persistence.impl.jdbc;

import com.arplanets.auth.repository.persistence.ClientRegistrationPersistentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;

@Repository
@RequiredArgsConstructor
@Slf4j
public class ClientRegistrationPersistentRepositoryJdbcImpl implements ClientRegistrationPersistentRepository {

    private final JdbcTemplate jdbcTemplate;

    @Override
    public List<Map<String, Object>> findAll() {
        try {
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
                    "post_logout_redirect_uris, " +
                    "token_uri, " +
                    "user_info_uri, " +
                    "jwk_set_uri, " +
                    "user_name_attribute_name, " +
                    "scopes " +
                    "FROM client_registration " +
                    "WHERE is_active = 1 " +
                    "AND deleted_at IS NULL";

            return jdbcTemplate.queryForList(sql);
        } catch (Exception e) {
            log.error("Failed to retrieve all ClientRegistrations from the database.", e);
            throw new DataAccessException("Failed to retrieve all ClientRegistrations due to a database error.", e) {};
        }
    }
}
