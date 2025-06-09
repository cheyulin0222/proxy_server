package com.arplanets.auth.repository.persistence.impl.jdbc;

import com.arplanets.auth.model.po.domain.ClaimMapping;
import com.arplanets.auth.repository.persistence.ClaimMappingRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

@Repository
@RequiredArgsConstructor
public class ClaimMappingRepositoryJdbcImpl implements ClaimMappingRepository {

    private final JdbcTemplate jdbcTemplate;

    @Override
    public List<ClaimMapping> findByRegistrationId(String registrationId) {
        String sql = "SELECT * FROM user_attribute_mapping WHERE registration_id = ? AND is_active = 1 AND deleted_at IS NULL";

        return jdbcTemplate.query(
                sql,
                ps -> ps.setString(1, registrationId),
                userAttributeMappingRowMapper());
    }

    @Override
    public List<ClaimMapping> findByRegistrationIdAndScopes(String registrationId, Set<String> scopes) {
        if (scopes == null || scopes.isEmpty()) {
            return List.of();
        }

        String inSql = String.join(",", Collections.nCopies(scopes.size(), "?"));

        String sql = "SELECT " +
                "uam.registration_id, " +
                "uam.claim_name, " +
                "uam.idp_claim_name, " +
                "uam.scope, " +
                "uam.is_active, " +
                "uam.created_at, " +
                "uam.updated_at, " +
                "uam.deleted_at " +
                "FROM user_attribute_mapping uam " +
                "INNER JOIN client_registration cr ON cr.registration_id = uam.registration_id " +
                "WHERE uam.registration_id = ? AND LOWER(uam.scope) IN (" + inSql + ") " +
                "AND cr.is_active = 1 AND cr.deleted_at IS NULL " +
                "AND uam.is_active = 1 AND uam.deleted_at IS NULL";

        return jdbcTemplate.query(
                sql,
                ps -> {
                    int index = 1;
                    ps.setString(index++, registrationId);
                    for (String scope : scopes) {
                        ps.setString(index++, (scope != null ? scope.toLowerCase() : null));
                    }
                },
                userAttributeMappingRowMapper()
        );
    }

    @Override
    public void saveAll(List<ClaimMapping> claimMappingList) {
        List<Object[]> batchArgs = new ArrayList<>();
        claimMappingList.forEach(mapping -> batchArgs.add(new Object[]{
                mapping.getRegistrationId(),
                mapping.getClaimName(),
                mapping.getIdpClaimName(),
                mapping.getScope()
        }));

        String sql = "INSERT IGNORE INTO user_attribute_mapping (registration_id, claim_name, idp_claim_name, scope) " +
                "VALUES (?, ?, ?, ?)";

        jdbcTemplate.batchUpdate(sql, batchArgs);
    }

    private RowMapper<ClaimMapping> userAttributeMappingRowMapper() {
        return (rs, rowNum) -> {
            try {
                return ClaimMapping.builder()
                        .registrationId(rs.getString("registration_id"))
                        .claimName(rs.getString("claim_name"))
                        .idpClaimName(rs.getString("idp_claim_name"))
                        .scope(rs.getString("scope"))
                        .isActive(rs.getBoolean("is_active"))
                        .createdAt(rs.getTimestamp("created_at") != null ? rs.getTimestamp("created_at").toInstant() : null)
                        .updatedAt(rs.getTimestamp("updated_at") != null ? rs.getTimestamp("updated_at").toInstant() : null)
                        .deletedAt(rs.getTimestamp("deleted_at") != null ? rs.getTimestamp("deleted_at").toInstant() : null)
                        .build();
            } catch (SQLException e) {
                throw new DataAccessException("Error mapping UserAttributeMapping from ResultSet", e) {};
            }
        };
    }
}
