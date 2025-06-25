package com.arplanets.auth.test;

import com.arplanets.auth.model.po.domain.AuthActivity;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;

@Repository
@RequiredArgsConstructor
public class AuthActivityRepositoryJdbcImpl implements AuthActivityRepository {

    private final JdbcTemplate jdbcTemplate;


    @Override
    public void save(AuthActivity authActivity) {
        String sql = "INSERT INTO auth_activity (" +
                "auth_session_id, refresh_token_value, access_token_value, user_id, action, ip, device_type, os_name, os_version, created_at)" +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        jdbcTemplate.update(
                sql,
                authActivity.getAuthId(),
                authActivity.getRefreshTokenValue(),
                authActivity.getAccessTokenValue(),
                authActivity.getUserId(),
                authActivity.getAction(),
                authActivity.getIp(),
                authActivity.getDeviceType(),
                authActivity.getOsName(),
                authActivity.getOsVersion(),
                authActivity.getCreatedAt() != null ? Timestamp.from(authActivity.getCreatedAt()) : null
        );
    }
}
