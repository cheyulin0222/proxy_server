package com.arplanets.auth.repository.persistence.impl.jdbc;

import com.arplanets.auth.model.po.domain.UserClaim;
import com.arplanets.auth.repository.persistence.UserInfoRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

@Repository
@RequiredArgsConstructor
@Slf4j
public class UserInfoRepositoryJdbcImpl implements UserInfoRepository {

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    @Override
    public void saveAll(List<UserClaim> claims) {
        List<Object[]> batchArgs = new ArrayList<>();

        claims.forEach(claim -> {
            Object rawValue = claim.getValue();
            String jsonValue;

            try {
                jsonValue = objectMapper.writeValueAsString(rawValue);

                batchArgs.add(new Object[]{
                        claim.getUserId(),
                        claim.getClaimName(),
                        jsonValue
                });

            } catch (JsonProcessingException e) {
                log.error("Failed to serialize claim value for user_id={}, claim_name={}. Raw value: {}",
                        claim.getUserId(), claim.getClaimName(), rawValue, e);
            }
        });

        if (batchArgs.isEmpty()) {
            log.warn("No valid claims to save.");
            return;
        }


        String sql = "INSERT INTO user_info (user_id, claim_name, value) " +
                "VALUES (?, ?, ?) " +
                "ON DUPLICATE KEY UPDATE value = VALUES(value)";

        try {
            jdbcTemplate.batchUpdate(sql, batchArgs);
        } catch (DataAccessException e) {
            log.error("Error executing batch update for user_info.", e);
            throw e;
        }
    }

    public List<UserClaim> findByUserId(String userId) {
        String sql = "SELECT * FROM user_info WHERE user_id = ?";

        return jdbcTemplate.query(sql, this::mapRowToUserClaim, userId);
    }

    private UserClaim mapRowToUserClaim(ResultSet rs, int rowNum) throws SQLException {

        JsonNode value = null;

        try {
            String valueString = rs.getString("value");
            if (valueString != null) {
                value = objectMapper.readTree(valueString);
            }
        } catch (Exception e) {
            log.error("Error parsing JSON value for user ID: {}, claim name: {}", rs.getString("user_id"), rs.getString("claim_name"), e);
        }

        return UserClaim.builder()
                .userId(rs.getString("user_id"))
                .claimName(rs.getString("claim_name"))
                .value(value)
                .build();
    }
}
