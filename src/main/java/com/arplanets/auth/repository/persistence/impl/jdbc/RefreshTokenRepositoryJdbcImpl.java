package com.arplanets.auth.repository.persistence.impl.jdbc;

import com.arplanets.auth.model.po.domain.RefreshToken;
import com.arplanets.auth.repository.persistence.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;

@Repository
@RequiredArgsConstructor
public class RefreshTokenRepositoryJdbcImpl implements RefreshTokenRepository {

    private final JdbcTemplate jdbcTemplate;

    @Override
    public void save(RefreshToken refreshToken) {
        String sql = "INSERT INTO refresh_token (" +
                "refresh_token_value, user_id, client_id, created_at, expires_at, auth_session_id)" +
                "VALUES (?, ?, ?, ?, ?, ?)";

        jdbcTemplate.update(
                sql,
                refreshToken.getRefreshTokenValue(),
                refreshToken.getUserId(),
                refreshToken.getClientId(),
                refreshToken.getCreatedAt() != null ? Timestamp.from(refreshToken.getCreatedAt()) : null,
                refreshToken.getExpiresAt() != null ? Timestamp.from(refreshToken.getExpiresAt()) : null,
                refreshToken.getAuthSessionId()
        );
    }
}
