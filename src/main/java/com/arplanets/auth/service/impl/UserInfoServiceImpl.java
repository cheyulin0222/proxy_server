package com.arplanets.auth.service.impl;

import com.arplanets.auth.model.po.domain.ClaimMapping;
import com.arplanets.auth.model.po.domain.UserClaim;
import com.arplanets.auth.repository.ClaimMappingRepository;
import com.arplanets.auth.repository.UserInfoRepository;
import com.arplanets.auth.service.UserInfoService;
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
    public void saveUserClaims(String uid, String registrationId, Map<String, Object> userInfo) {

        // 1. 獲取需要的欄位
        List<ClaimMapping> claimMappingList = claimMappingRepository.findByRegistrationId(registrationId);
        if (claimMappingList == null || claimMappingList.isEmpty()) {
            return;
        }

        List<UserClaim> finalClaims = claimMappingList.stream()
                .filter(mapping -> userInfo.containsKey(mapping.getIdpClaimName()))
                .map(mapping -> UserClaim.builder()
                        .userId(uid)
                        .claimName(mapping.getClaimName())
                        .value(userInfo.get(mapping.getIdpClaimName()))
                        .build())
                .toList();

        if (finalClaims.isEmpty()) return;

        userInfoRepository.saveAll(finalClaims);

    }

}
