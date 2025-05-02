package com.arplanets.auth.repository;

import com.arplanets.auth.component.UserPoolContext;
import com.arplanets.auth.component.UserPoolContextHolder;
import com.arplanets.auth.model.po.domain.ExtendedRegisteredClient;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Map;


public class ExtendedJdbcRegisteredClientRepository extends JdbcRegisteredClientRepository {

    private final JdbcOperations jdbcOperations;

    public ExtendedJdbcRegisteredClientRepository(JdbcOperations jdbcOperations) {
        super(jdbcOperations);
        this.jdbcOperations = jdbcOperations;
    }


    @Override
    public RegisteredClient findById(String id) {
        RegisteredClient client = super.findById(id);
        if (client != null) {

            try {
                Boolean isActive = jdbcOperations.queryForObject(
                        "SELECT is_active FROM oauth2_registered_client WHERE id = ? AND deleted_at IS NULL",
                        Boolean.class,
                        id);

                if (isActive == null || !isActive) {
                    return null;
                }
            } catch (EmptyResultDataAccessException e) {
                return null;
            }
        }
        return client;
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        RegisteredClient client = super.findByClientId(clientId);

        if (client != null) {

            try {
                Boolean isActive = jdbcOperations.queryForObject(
                        "SELECT is_active FROM oauth2_registered_client WHERE id = ? AND deleted_at IS NULL",
                        Boolean.class,
                        client.getId());

                if (isActive == null || !isActive) {
                    return null;
                }
            } catch (EmptyResultDataAccessException e) {
                return null;
            }
        }
        return client;
    }


    public void setClientActive(String id, boolean active) {
        String sql = "UPDATE oauth2_registered_client SET is_active = ?, updated_at = ? WHERE id = ?";
        jdbcOperations.update(sql,
                active,
                Timestamp.from(Instant.now()),
                id);
    }

    // 軟刪除
    public void markDeleted(String id) {
        Instant now = Instant.now();
        String sql = "UPDATE oauth2_registered_client SET is_active = ?, updated_at = ?, deleted_at = ? WHERE id = ?";
        jdbcOperations.update(sql,
                false,
                Timestamp.from(now),
                Timestamp.from(now),
                id);
    }

    public ExtendedRegisteredClient findExtendedById(String id) {
        RegisteredClient client = findById(id);
        if (client == null) {
            return null;
        }

        try {
            Map<String, Object> result = jdbcOperations.queryForMap(
                    "SELECT is_active, updated_at, deleted_at FROM oauth2_registered_client WHERE id = ?",
                    id);

            return new ExtendedRegisteredClient(
                    client,
                    (Boolean) result.get("is_active"),
                    result.get("updated_at") != null ? ((Timestamp) result.get("updated_at")).toInstant() : null,
                    result.get("deleted_at") != null ? ((Timestamp) result.get("deleted_at")).toInstant() : null
            );
        } catch (EmptyResultDataAccessException e) {
            return null;
        }
    }

    public ExtendedRegisteredClient findExtendedByClientId(String clientId) {
        RegisteredClient client = findByClientId(clientId);
        if (client == null) {
            return null;
        }

        return findExtendedById(client.getId());
    }

    private String getCurrentUserPoolId() {
        UserPoolContext context = UserPoolContextHolder.getContext();
        return context.getUserPoolId();
    }




}
