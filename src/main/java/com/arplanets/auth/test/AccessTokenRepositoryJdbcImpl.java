package com.arplanets.auth.test;

import com.arplanets.auth.model.po.domain.AccessToken;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;

@Repository
@RequiredArgsConstructor
public class AccessTokenRepositoryJdbcImpl implements AccessTokenRepository {

    private final JdbcTemplate jdbcTemplate;

    @Override
    public void save(AccessToken accessToken) {
        String sql = "INSERT INTO access_token (" +
                "access_token_value, user_id, client_id, created_at, expires_at, auth_session_id, refresh_token_value) " +
                "VALUES (?, ?, ?, ? , ?, ?, ?)";

        jdbcTemplate.update(
                sql,
                accessToken.getAccessTokenValue(),
                accessToken.getUserId(),
                accessToken.getClientId(),
                accessToken.getCreatedAt() != null ? Timestamp.from(accessToken.getCreatedAt()) : null,
                accessToken.getExpiresAt() != null ? Timestamp.from(accessToken.getExpiresAt()) : null,
                accessToken.getAuthId(),
                accessToken.getRefreshTokenValue()
        );
    }
}
