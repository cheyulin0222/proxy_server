package com.arplanets.auth.model.po.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ClientRegistrationMapping {

    private String clientId;

    private String registrationId;
}
