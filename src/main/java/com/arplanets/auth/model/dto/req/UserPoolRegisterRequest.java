package com.arplanets.auth.model.dto.req;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

import java.util.List;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserPoolRegisterRequest {

    @NotBlank
    private String userPoolId;

    @NotBlank
    private String poolName;

    @NotNull
    private Set<String> scopes;

    @NotBlank
    private String jwkSet;

    @NotNull
    private List<ClientRegistration> clientRegistrations;
}
