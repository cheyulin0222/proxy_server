package com.arplanets.auth.repository.persistence.impl.jdbc;

import com.arplanets.auth.model.UserPoolContextHolder;
import com.arplanets.auth.repository.persistence.RegisteredClientPersistentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.*;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Repository;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

@Repository
@RequiredArgsConstructor
public class RegisteredClientPersistentRepositoryJdbcImpl implements RegisteredClientPersistentRepository {

    private final JdbcOperations jdbcOperations;
    private final RowMapper<RegisteredClient> registeredClientRowMapper = new JdbcRegisteredClientRepository.RegisteredClientRowMapper();
    private final Function<RegisteredClient, List<SqlParameterValue>> registeredClientParametersMapper = new JdbcRegisteredClientRepository.RegisteredClientParametersMapper();


    private static final String COLUMN_NAMES = "id, client_id, client_id_issued_at, client_secret, client_secret_expires_at, " +
            "client_name, client_authentication_methods, authorization_grant_types, redirect_uris, " +
            "post_logout_redirect_uris, scopes, client_settings, token_settings";

    private static final String TABLE_NAME = "oauth2_registered_client";

    private static final String LOAD_REGISTERED_CLIENT_SQL = "SELECT " + COLUMN_NAMES +
            " FROM " + TABLE_NAME +
            " WHERE ";

    private static final String UPDATE_REGISTERED_CLIENT_SQL = "UPDATE " + TABLE_NAME +
            " SET client_id =?, client_id_issued_at =?, client_secret =?, client_secret_expires_at =?, " +
            "client_name =?, client_authentication_methods =?, authorization_grant_types =?, " +
            "redirect_uris =?, post_logout_redirect_uris =?, scopes =?, client_settings =?, token_settings =? " +
            "WHERE id =? AND user_pool_id =?";

    private static final String INSERT_REGISTERED_CLIENT_SQL = "INSERT INTO " + TABLE_NAME +
            "(" + COLUMN_NAMES + ", user_pool_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    private static final String LOAD_BY_ID_SQL = LOAD_REGISTERED_CLIENT_SQL +
            "id =? AND user_pool_id =? AND is_active = 1 AND deleted_at IS NULL";

    private static final String LOAD_BY_CLIENT_ID_SQL = LOAD_REGISTERED_CLIENT_SQL +
            "client_id =? AND user_pool_id =? AND is_active = 1 AND deleted_at IS NULL";


    @Override
    public void save(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        RegisteredClient existingClient = findById(registeredClient.getId());
        if (existingClient!= null) {
            update(registeredClient);
        } else {
            insert(registeredClient);
        }
    }

    @Override
    public RegisteredClient findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return findBy(LOAD_BY_ID_SQL, id, getCurrentUserPoolId());
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Assert.hasText(clientId, "clientId cannot be empty");
        return findBy(LOAD_BY_CLIENT_ID_SQL, clientId, getCurrentUserPoolId());
    }

    @Override
    public String findUserPoolIdByClientId(String clientId) {
        Assert.hasText(clientId, "clientId cannot be empty");
        String sql = "SELECT user_pool_id FROM " + TABLE_NAME + " WHERE client_id = ?";
        return jdbcOperations.queryForObject(sql, String.class, clientId);
    }


    public void update(RegisteredClient registeredClient) {
        List<SqlParameterValue> parameters = this.registeredClientParametersMapper.apply(registeredClient);
        List<SqlParameterValue> updateParameters = new ArrayList<>(parameters.subList(1, parameters.size()));
        updateParameters.add(parameters.get(0));
        updateParameters.add(new SqlParameterValue(java.sql.Types.VARCHAR, getCurrentUserPoolId()));

        PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(updateParameters.toArray());
        this.jdbcOperations.update(UPDATE_REGISTERED_CLIENT_SQL, pss);
    }

    public void insert(RegisteredClient registeredClient) {
        List<SqlParameterValue> originalParameters = this.registeredClientParametersMapper.apply(registeredClient);
        List<SqlParameterValue> parameters = new ArrayList<>(originalParameters);
        parameters.add(new SqlParameterValue(java.sql.Types.VARCHAR, getCurrentUserPoolId()));
        PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
        this.jdbcOperations.update(INSERT_REGISTERED_CLIENT_SQL, pss);
    }

    public RegisteredClient findBy(String sql, Object... args) {
        List<RegisteredClient> result = this.jdbcOperations.query(sql, this.registeredClientRowMapper, args);
        return!CollectionUtils.isEmpty(result)? result.get(0) : null;
    }


    private String getCurrentUserPoolId() {
        String userPoolId = UserPoolContextHolder.getContext().userPoolId();
        Assert.hasText(userPoolId, "User Pool ID cannot be empty in the current context");
        return userPoolId;
    }
}
