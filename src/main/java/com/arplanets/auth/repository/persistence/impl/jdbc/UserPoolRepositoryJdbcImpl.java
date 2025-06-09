package com.arplanets.auth.repository.persistence.impl.jdbc;

import com.arplanets.auth.model.po.domain.UserPool;
import com.arplanets.auth.repository.persistence.UserPoolRepository;
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

    private static final String FIND_ALL_SQL = """
        SELECT
            user_pool_id, pool_name, scopes, jwk_set,
            is_active, created_at, updated_at, deleted_at
        FROM user_pool
        WHERE is_active = true AND deleted_at IS NULL
        ORDER BY pool_name ASC
        """;

    @Override
    public List<UserPool> findAll() {
        try {
            return jdbcTemplate.query(FIND_ALL_SQL, userPoolRowMapper());
        } catch (Exception e) {
            log.error("Failed to retrieve all UserPools from the database.", e);
            throw new DataAccessException("Failed to retrieve all UserPools due to a database error.", e) {};
        }
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
