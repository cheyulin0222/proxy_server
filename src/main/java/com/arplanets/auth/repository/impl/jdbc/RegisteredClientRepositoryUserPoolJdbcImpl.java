package com.arplanets.auth.repository.impl.jdbc;

import com.arplanets.auth.component.UserPoolContextHolder;
import org.springframework.jdbc.core.*;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Repository;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;


public class RegisteredClientRepositoryUserPoolJdbcImpl implements RegisteredClientRepository {

    // Base column list from JdbcRegisteredClientRepository, add your custom columns if needed
    private static final String COLUMN_NAMES = "id, client_id, client_id_issued_at, client_secret, client_secret_expires_at, " +
            "client_name, client_authentication_methods, authorization_grant_types, redirect_uris, " +
            "post_logout_redirect_uris, scopes, client_settings, token_settings"; // Add is_active if needed by mapper

    private static final String TABLE_NAME = "oauth2_registered_client";

    // IMPORTANT: Add user_pool_id, is_active, and deleted_at checks to WHERE clauses
    private static final String LOAD_REGISTERED_CLIENT_SQL = "SELECT " + COLUMN_NAMES +
            " FROM " + TABLE_NAME +
            " WHERE "; // Base query

    private static final String LOAD_BY_ID_SQL = LOAD_REGISTERED_CLIENT_SQL +
            "id =? AND user_pool_id =? AND is_active = 1 AND deleted_at IS NULL";

    private static final String LOAD_BY_CLIENT_ID_SQL = LOAD_REGISTERED_CLIENT_SQL +
            "client_id =? AND user_pool_id =? AND is_active = 1 AND deleted_at IS NULL";

    private static final String INSERT_REGISTERED_CLIENT_SQL = "INSERT INTO " + TABLE_NAME +
            "(" + COLUMN_NAMES + ", user_pool_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    private static final String UPDATE_REGISTERED_CLIENT_SQL = "UPDATE " + TABLE_NAME +
            " SET client_id =?, client_id_issued_at =?, client_secret =?, client_secret_expires_at =?, " +
            "client_name =?, client_authentication_methods =?, authorization_grant_types =?, " +
            "redirect_uris =?, post_logout_redirect_uris =?, scopes =?, client_settings =?, token_settings =? " +
            "WHERE id =? AND user_pool_id =?";


    private final JdbcOperations jdbcOperations;
    private final RowMapper<RegisteredClient> registeredClientRowMapper;
    private final Function<RegisteredClient, List<SqlParameterValue>> registeredClientParametersMapper;

    public RegisteredClientRepositoryUserPoolJdbcImpl(JdbcOperations jdbcOperations) {
        Assert.notNull(jdbcOperations, "JdbcOperations cannot be null");
        this.jdbcOperations = jdbcOperations;
        this.registeredClientRowMapper = new JdbcRegisteredClientRepository.RegisteredClientRowMapper();
        this.registeredClientParametersMapper = new JdbcRegisteredClientRepository.RegisteredClientParametersMapper();
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        RegisteredClient existingClient = findByIdInternal(registeredClient.getId());
        if (existingClient!= null) {
            updateRegisteredClient(registeredClient);
        } else {
            insertRegisteredClient(registeredClient);
        }
    }

    @Nullable
    @Override
    public RegisteredClient findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return findBy(LOAD_BY_ID_SQL, id, getCurrentUserPoolId()); // Includes active/deleted checks
    }

    @Nullable
    @Override
    public RegisteredClient findByClientId(String clientId) {
        Assert.hasText(clientId, "clientId cannot be empty");
        return findBy(LOAD_BY_CLIENT_ID_SQL, clientId, getCurrentUserPoolId());
    }

    public String findUserPoolIdByClientId(String clientId) {
        Assert.hasText(clientId, "clientId cannot be empty");
        String sql = "SELECT user_pool_id FROM " + TABLE_NAME + " WHERE client_id = ?";
        return jdbcOperations.queryForObject(sql, String.class, clientId);
    }

    private String getCurrentUserPoolId() {
        String userPoolId = UserPoolContextHolder.getContext().getUserPoolId();
        Assert.hasText(userPoolId, "User Pool ID cannot be empty in the current context");
        return userPoolId;
    }

    @Nullable
    private RegisteredClient findByIdInternal(String id) {
        String sql = LOAD_REGISTERED_CLIENT_SQL + "id =? AND user_pool_id =? AND is_active = 1 AND deleted_at IS NULL";
        return findBy(sql, id, getCurrentUserPoolId());
    }

    @Nullable
    private RegisteredClient findBy(String sql, Object... args) {
        List<RegisteredClient> result = this.jdbcOperations.query(sql, this.registeredClientRowMapper, args);
        return!CollectionUtils.isEmpty(result)? result.get(0) : null;
    }

    private void updateRegisteredClient(RegisteredClient registeredClient) {
        List<SqlParameterValue> parameters = this.registeredClientParametersMapper.apply(registeredClient);
        // The standard mapper gives parameters in order for INSERT. Need to reorder for UPDATE.
        List<SqlParameterValue> updateParameters = new ArrayList<>();
        // Add all parameters EXCEPT the first one (id)
        updateParameters.addAll(parameters.subList(1, parameters.size()));
        // Add the id parameter at the end for the WHERE clause
        updateParameters.add(parameters.get(0));
        // Add the user_pool_id for the WHERE clause
        updateParameters.add(new SqlParameterValue(java.sql.Types.VARCHAR, getCurrentUserPoolId()));

        PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(updateParameters.toArray());
        this.jdbcOperations.update(UPDATE_REGISTERED_CLIENT_SQL, pss);
    }

    private void insertRegisteredClient(RegisteredClient registeredClient) {
        List<SqlParameterValue> parameters = this.registeredClientParametersMapper.apply(registeredClient);
        // Add the user_pool_id as the last parameter for the INSERT statement
        parameters.add(new SqlParameterValue(java.sql.Types.VARCHAR, getCurrentUserPoolId()));
        PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
        this.jdbcOperations.update(INSERT_REGISTERED_CLIENT_SQL, pss);
    }
}
