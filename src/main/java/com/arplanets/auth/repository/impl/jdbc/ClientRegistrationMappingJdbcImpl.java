package com.arplanets.auth.repository.impl.jdbc;

import com.arplanets.auth.model.po.domain.ClientRegistrationMapping;
import com.arplanets.auth.repository.ClientRegistrationMappingRepository;
import com.arplanets.auth.utils.JsonUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.NonNull;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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

        return jdbcTemplate.query(sql, new ClientRegistrationMappingJdbcImpl.ClientRegistrationRowMapper(), clientId);

    }

    private static class ClientRegistrationRowMapper implements RowMapper<ClientRegistration> {
        @Override
        public ClientRegistration mapRow(@NonNull ResultSet rs, int rowNum) throws SQLException {
            // 直接在 mapRow 方法中处理异常
            Set<String> scopes = new HashSet<>();
            try{
                scopes = JsonUtil.convertJsonStringToSet(rs.getString("scopes"), String.class);
            }catch (Exception e){
                //ignore
                //log
            }

            return ClientRegistration.withRegistrationId(rs.getString("registration_id"))
                    .clientName(rs.getString("provider_name"))
                    .clientId(rs.getString("client_id"))
                    .clientSecret(rs.getString("client_secret"))
                    .clientAuthenticationMethod(new ClientAuthenticationMethod(rs.getString("client_authentication_method")))
                    .authorizationGrantType(new AuthorizationGrantType(rs.getString("authorization_grant_type")))
                    .redirectUri(rs.getString("redirect_uri"))
                    .authorizationUri(rs.getString("authorization_uri"))
                    .tokenUri(rs.getString("token_uri"))
                    .userInfoUri(rs.getString("user_info_uri"))
                    .jwkSetUri(rs.getString("jwk_set_uri"))
                    .userNameAttributeName(rs.getString("user_name_attribute_name"))
                    .scope(scopes)
                    .build();
        }
    }
}
