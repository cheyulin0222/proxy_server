package com.arplanets.auth.test;

import com.arplanets.auth.utils.JsonUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;

@RequiredArgsConstructor
@Slf4j
@Repository
public class CustomClientRegistrationRepository{

    private final JdbcTemplate jdbcTemplate;

    public List<Map<String, Object>> findAll() {
        String sql = "SELECT " +
                "* " +
                "FROM client_registration " +
                "WHERE is_active = 1 " +
                "AND deleted_at IS NULL";

        return jdbcTemplate.queryForList(sql);
    }

    public boolean existsById(String id) {
        String sql = "SELECT COUNT(*) FROM client_registration WHERE registration_id = ?";

        Integer count = jdbcTemplate.queryForObject(
                sql,
                Integer.class,
                id
        );

        return count != null && count > 0;
    }

    public void insert(ClientRegistration clientRegistration) {
        String sql = "INSERT INTO client_registration(" +
                "registration_id, " +
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
                "scopes" +
                ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        String scopes = JsonUtil.convertSetToJsonString(clientRegistration.getScopes());

        jdbcTemplate.update(
                sql,
                clientRegistration.getRegistrationId(),
                clientRegistration.getClientName(),
                clientRegistration.getClientId(),
                clientRegistration.getClientSecret(),
                clientRegistration.getClientAuthenticationMethod().getValue(),
                clientRegistration.getAuthorizationGrantType().getValue(),
                clientRegistration.getRedirectUri(),
                clientRegistration.getProviderDetails().getAuthorizationUri(),
                clientRegistration.getProviderDetails().getTokenUri(),
                clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri(),
                clientRegistration.getProviderDetails().getJwkSetUri(),
                clientRegistration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName(),
                scopes
        );
    }

    public static class ClientRegistrationRowMapper implements RowMapper<ClientRegistration> {
        @Override
        public ClientRegistration mapRow(ResultSet rs, int rowNum) throws SQLException {
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
