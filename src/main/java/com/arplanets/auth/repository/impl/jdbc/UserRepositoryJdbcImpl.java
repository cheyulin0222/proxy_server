package com.arplanets.auth.repository.impl.jdbc;

import com.arplanets.auth.model.po.domain.User;
import com.arplanets.auth.repository.UserRepository;
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
        String sql = "INSERT INTO user (user_id) VALUES (?)";

        jdbcTemplate.update(sql, user.getUserId());

        Optional<User> option = findById(user.getUserId());

        return option.orElse(null);

    }

    @Override
    public boolean existsById(String id) {
        String sql = "SELECT COUNT(*) FROM user WHERE user_id = ?";

        Integer count = jdbcTemplate.queryForObject(
                sql,
                Integer.class,
                id
        );

        return count != null && count > 0;
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

    private static class UserRowMapper implements RowMapper<User> {
        @Override
        public User mapRow(ResultSet rs, int rowNum) throws SQLException {

            return User.builder()
                    .userId(rs.getString("user_id"))
                    .isActive(rs.getBoolean("is_active")) // 假设数据库中有 is_active 列
                    .createdAt(rs.getTimestamp("created_at") != null ? rs.getTimestamp("created_at").toLocalDateTime() : null)
                    .updatedAt(rs.getTimestamp("updated_at") != null ? rs.getTimestamp("updated_at").toLocalDateTime() : null)
                    .deletedAt(rs.getTimestamp("deleted_at") != null ? rs.getTimestamp("deleted_at").toLocalDateTime() : null)
                    .build();
        }
    }
}
