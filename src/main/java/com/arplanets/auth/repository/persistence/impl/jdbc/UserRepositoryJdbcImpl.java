package com.arplanets.auth.repository.persistence.impl.jdbc;

import com.arplanets.auth.model.po.domain.User;
import com.arplanets.auth.repository.persistence.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class UserRepositoryJdbcImpl implements UserRepository {

    private final JdbcTemplate jdbcTemplate;

    @Override
    public User insert(User user) {
        String sql = "INSERT INTO user (user_id, registration_id, idp_sub) VALUES (?, ?, ?)";

        jdbcTemplate.update(sql, user.getUserId(), user.getRegistrationId(), user.getIdpSub());

        Optional<User> option = findById(user.getUserId());

        return option.orElseThrow(() -> new IllegalStateException("Failed to retrieve user after successful insertion: " + user.getUserId()));
    }

    @Override
    public Optional<User> findById(String id) {
        String sql = "SELECT * FROM user WHERE user_id = ?";

        try {
            User user = jdbcTemplate.queryForObject(sql, new UserRepositoryJdbcImpl.UserRowMapper(), id);
            return Optional.ofNullable(user);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    @Override
    public Optional<User> findByRegistrationIdAndIdpSub(String registrationId, String idpSub) {
        String sql = "SELECT * FROM user WHERE registration_id = ? AND idp_sub = ?";
        try {
            User user = jdbcTemplate.queryForObject(sql, new UserRepositoryJdbcImpl.UserRowMapper(), registrationId, idpSub);
            return Optional.ofNullable(user);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    private static class UserRowMapper implements RowMapper<User> {
        @Override
        public User mapRow(ResultSet rs, int rowNum) throws SQLException {

            return User.builder()
                    .userId(rs.getString("user_id"))
                    .registrationId(rs.getString("registration_id"))
                    .idpSub(rs.getString("idp_sub"))
                    .isActive(rs.getBoolean("is_active")) // 假设数据库中有 is_active 列
                    .createdAt(rs.getTimestamp("created_at") != null ? rs.getTimestamp("created_at").toLocalDateTime() : null)
                    .updatedAt(rs.getTimestamp("updated_at") != null ? rs.getTimestamp("updated_at").toLocalDateTime() : null)
                    .deletedAt(rs.getTimestamp("deleted_at") != null ? rs.getTimestamp("deleted_at").toLocalDateTime() : null)
                    .build();
        }
    }
}
