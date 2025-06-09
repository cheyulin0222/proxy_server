package com.arplanets.auth.controller;

import com.arplanets.auth.model.dto.req.UserPoolRegisterRequest;
import com.arplanets.auth.repository.inmemory.TenantRepository;
import com.arplanets.auth.model.po.domain.UserPool;
import com.arplanets.auth.service.inmemory.TenantJwkService;
import com.arplanets.auth.service.inmemory.InMemoryClientRegistrationService;
import com.arplanets.auth.service.inmemory.UserPoolInfoService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.web.bind.annotation.*;
import software.amazon.awssdk.annotations.NotNull;

import java.util.List;

@RestController
@RequestMapping("/resources/user-pool")
@RequiredArgsConstructor
@Slf4j
public class UserPoolController {

    private final TenantRepository tenantRepository;
    private final UserPoolInfoService userPoolInfoService;
    private final TenantJwkService tenantJwkService;
    private final InMemoryClientRegistrationService inMemoryClientRegistrationService;


    @PostMapping(produces = {MediaType.APPLICATION_JSON_VALUE})
    public void register(@Valid @RequestBody UserPoolRegisterRequest request) {

        String userPoolId = request.getUserPoolId();
        String poolName = request.getPoolName();

        UserPool userPool = UserPool.builder()
                .userPoolId(request.getUserPoolId())
                .poolName(request.getPoolName())
                .scopes(request.getScopes())
                .jwkSet(request.getJwkSet())
                .build();

        List<ClientRegistration> clientRegistrations = request.getClientRegistrations();

        try {
            tenantJwkService.registerUserPoolJwkSet(userPool);
            userPoolInfoService.registerUserPoolInfo(userPool);
            clientRegistrations.forEach(clientRegistration -> {
                try {
                    inMemoryClientRegistrationService.register(userPool.getUserPoolId(), clientRegistration);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        } catch (Exception e) {
            tenantRepository.remove(poolName);
            inMemoryClientRegistrationService.removeByUserPoolId(userPoolId);
            throw new RuntimeException(e);
        }

    }

    @DeleteMapping(value = "/{poolName}", produces = {MediaType.APPLICATION_JSON_VALUE})
    public void remove(@PathVariable @NotNull String poolName) {

        String userPoolId = userPoolInfoService.findByPoolName(poolName).getUserPoolId();

        tenantRepository.remove(poolName);
        inMemoryClientRegistrationService.removeByUserPoolId(userPoolId);
    }
}
