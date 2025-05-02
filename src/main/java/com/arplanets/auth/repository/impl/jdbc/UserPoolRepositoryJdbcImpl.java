package com.arplanets.auth.repository.impl.jdbc;

import com.arplanets.auth.model.po.domain.UserPool;
import com.arplanets.auth.repository.UserPoolRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;
import org.springframework.util.StringUtils;

import java.sql.SQLException;
import java.util.Collections;
import java.util.List;
import java.util.Set;

@Repository
@RequiredArgsConstructor
@Slf4j
public class UserPoolRepositoryJdbcImpl implements UserPoolRepository {

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    private static final String FIND_BY_ID_SQL = """
        SELECT
            user_pool_id,
            pool_name,
            scopes,
            jwk_set,
            is_active,
            created_at,
            updated_at,
            deleted_at
        FROM user_pool
        WHERE user_pool_id = ?
          AND is_active = 1
          AND deleted_at IS NULL
        """;

    private static final String FIND_BY_POOL_NAME_SQL = """
        SELECT
            user_pool_id,
            pool_name,
            scopes,
            jwk_set,
            is_active,
            created_at,
            updated_at,
            deleted_at
        FROM user_pool
        WHERE pool_name = ?
          AND is_active = 1
          AND deleted_at IS NULL
        """;

    private static final String FIND_ALL_SQL = """
        SELECT
            user_pool_id, pool_name, scopes, jwk_set,
            is_active, created_at, updated_at, deleted_at
        FROM user_pool
        WHERE is_active = true AND deleted_at IS NULL
        ORDER BY pool_name ASC
        """;

    private static final String INSERT_SQL = """
        INSERT INTO user_pool
            (user_pool_id, pool_name, scopes, jwk_set)
        VALUES
            (?, ?, ?, ?)
        """;

    @Override
    public UserPool findById(String userPoolId) {
        List<UserPool> results = jdbcTemplate.query(
                FIND_BY_ID_SQL,
                userPoolRowMapper(),
                userPoolId
        );

        if (results.isEmpty()) {
            return null;
        }

        return results.get(0);

    }

    @Override
    public UserPool findByPoolName(String poolName) {
        return jdbcTemplate.queryForObject(
                FIND_BY_POOL_NAME_SQL,
                userPoolRowMapper(),
                poolName
        );
    }

    @Override
    public List<UserPool> findAll() {
        try {
            return jdbcTemplate.query(FIND_ALL_SQL, userPoolRowMapper());
        } catch (DataAccessException e) {
            log.error("查找所有活動的 UserPool 時資料庫出錯", e);
            return Collections.emptyList();
        }
    }

    @Override
    public UserPool save(UserPool userPool) {
        if (!StringUtils.hasText(userPool.getUserPoolId())) {
            throw new IllegalArgumentException("儲存前必須提供 UserPoolId");
        }
        if (!StringUtils.hasText(userPool.getPoolName())) {
            throw new IllegalArgumentException("儲存前必須提供 PoolName (來自 pool_name)");
        }

        String scopesJsonString = null;
        if (userPool.getScopes() != null && !userPool.getScopes().isEmpty()) {
            try {
                scopesJsonString = objectMapper.writeValueAsString(userPool.getScopes());
            } catch (JsonProcessingException e) {
                log.error("序列化 UserPool ID {} 的 scopes 時出錯: {}", userPool.getUserPoolId(), e.getMessage());
                throw new DataAccessException("無法序列化 scopes 為 JSON", e) {};
            }
        }

        log.info("即將新增UserPool");

        jdbcTemplate.update(
            INSERT_SQL,
            userPool.getUserPoolId(),
            userPool.getPoolName(),
            scopesJsonString,
            userPool.getJwkSet()
        );

        log.info("UserPool新增成功");

        return findById(userPool.getUserPoolId());

    }

    private RowMapper<UserPool> userPoolRowMapper() {
        return (rs, rowNum) -> {

            Set<String> scopes = Collections.emptySet();
            String scopesJson = rs.getString("scopes");
            if (StringUtils.hasText(scopesJson)) {
                try {
                    scopes = objectMapper.readValue(scopesJson,new TypeReference<>() {});
                } catch (JsonProcessingException e) {
                    throw new DataAccessException("Error mapping scopes from JSON for UserPool", e) {};
                }
            }

            try {
                return UserPool.builder()
                        .userPoolId(rs.getString("user_pool_id"))
                        .poolName(rs.getString("pool_name"))
                        .scopes(scopes)
                        .jwkSet(rs.getString("jwk_set"))
                        .isActive(rs.getBoolean("is_active"))
                        .createdAt(rs.getTimestamp("created_at") != null ? rs.getTimestamp("created_at").toInstant() : null)
                        .updatedAt(rs.getTimestamp("updated_at") != null ? rs.getTimestamp("updated_at").toInstant() : null)
                        .deletedAt(rs.getTimestamp("deleted_at") != null ? rs.getTimestamp("deleted_at").toInstant() : null)
                        .build();
            } catch (SQLException e) {
                throw new DataAccessException("Error mapping UserPool from ResultSet", e) {};
            }
        };
    }
}
