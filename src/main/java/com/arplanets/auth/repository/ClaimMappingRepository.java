package com.arplanets.auth.repository;

import com.arplanets.auth.model.po.domain.ClaimMapping;

import java.util.List;
import java.util.Set;

public interface ClaimMappingRepository {

    List<ClaimMapping> findByRegistrationId(String registrationId);
    List<ClaimMapping> findByRegistrationIdAndScopes(String registrationId, Set<String> scopes);
    void saveAll(List<ClaimMapping> claimMappingList);
}
