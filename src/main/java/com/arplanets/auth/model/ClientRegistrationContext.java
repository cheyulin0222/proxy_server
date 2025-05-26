package com.arplanets.auth.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ClientRegistrationContext {

    private ClientRegistration clientRegistration;
    private String userPoolId;
}
