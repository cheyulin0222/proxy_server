package com.arplanets.auth.service.persistence.impl;

import com.arplanets.auth.model.po.domain.ClaimMapping;
import com.arplanets.auth.model.po.domain.UserClaim;
import com.arplanets.auth.repository.persistence.ClaimMappingRepository;
import com.arplanets.auth.repository.persistence.UserInfoRepository;
import com.arplanets.auth.service.persistence.UserInfoService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class UserInfoServiceImpl implements UserInfoService {

    private final UserInfoRepository userInfoRepository;
    private final ClaimMappingRepository claimMappingRepository;

    @Override
    public void saveUserClaims(String uid, String registrationId, Map<String, Object> idpClaims) {

        // 1. 獲取需要的欄位
        List<ClaimMapping> claimMappingList = claimMappingRepository.findByRegistrationId(registrationId);
        if (claimMappingList == null || claimMappingList.isEmpty()) {
            return;
        }

        List<UserClaim> finalClaims = claimMappingList.stream()
                .filter(mapping -> idpClaims.containsKey(mapping.getIdpClaimName()))
                .map(mapping -> UserClaim.builder()
                        .userId(uid)
                        .claimName(mapping.getClaimName())
                        .value(idpClaims.get(mapping.getIdpClaimName()))
                        .build())
                .toList();

        if (finalClaims.isEmpty()) return;

        userInfoRepository.saveAll(finalClaims);

    }

}
