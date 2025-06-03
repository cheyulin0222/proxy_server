package com.arplanets.auth.repository.impl.jdbc;

import com.arplanets.auth.repository.ClientRegistrationPersistentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;

@Repository
@RequiredArgsConstructor
public class ClientRegistrationPersistentRepositoryJdbcImpl implements ClientRegistrationPersistentRepository {

    private final JdbcTemplate jdbcTemplate;

    @Override
    public List<Map<String, Object>> findAll() {
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
