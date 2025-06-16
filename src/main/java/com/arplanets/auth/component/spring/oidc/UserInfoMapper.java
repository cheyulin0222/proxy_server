package com.arplanets.auth.component.spring.oidc;

import com.arplanets.auth.model.po.domain.ClaimMapping;
import com.arplanets.auth.model.po.domain.UserClaim;
import com.arplanets.auth.repository.persistence.ClaimMappingRepository;
import com.arplanets.auth.repository.persistence.UserInfoRepository;
import com.arplanets.auth.utils.StringUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * 客製化 OIDC UserInfo 端點資訊
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class UserInfoMapper implements Function<OidcUserInfoAuthenticationContext, OidcUserInfo> {

    private final UserInfoRepository userInfoRepository;
    private final ClaimMappingRepository claimMappingRepository;
    private final ObjectMapper objectMapper;

    @Override
    public OidcUserInfo apply(OidcUserInfoAuthenticationContext context) {

        OAuth2Authorization authorization = context.getAuthorization();
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();

        // 取得 Access Token 的所有 claims
        Map<String, Object> claims = accessToken.getClaims();
        // 取得合法的 sub
        String sub = getValidatedSub(authorization);
        // 取得 Scopes
        Set<String> scopes = getScopes(context);

        // 以 sub、claims、scopes 取得最終回傳的 claims
        Map<String, Object> finalClaims = generateClaims(sub, claims, scopes);

        log.info("Retrieved OidcUserInfo");

        return new OidcUserInfo(finalClaims);
    }

    private Map<String, Object> generateClaims(String sub, Map<String, Object> claims, Set<String> scopes) {

        // 若 claims 不存在，僅回傳 sub
        if (claims == null) {
            return buildSingleClaim(sub);
        }

        // 取得 registration_id
        String registrationId = (String) claims.get(StringUtil.REGISTRATION_ID_ATTRIBUTE_NAME);

        // 若 registration_id、scopes 不存在，僅回傳 sub
        if (!StringUtils.hasText(registrationId) || CollectionUtils.isEmpty(scopes)) {
            return buildSingleClaim(sub);
        }

        // 以 registration_id、scopes 查詢需要回傳的 claims
        List<ClaimMapping> claimMappings = claimMappingRepository.findByRegistrationIdAndScopes(registrationId, scopes);

        // 若沒有要回傳的 claims ，僅回傳 sub
        if (CollectionUtils.isEmpty(claimMappings)) {
            return buildSingleClaim(sub);
        }

        // 取得 user 相關資訊
        List<UserClaim> userClaims = userInfoRepository.findByUserId(sub);

        // 若沒有 user 資訊 ，僅回傳 sub
        if (CollectionUtils.isEmpty(userClaims)) {
            return buildSingleClaim(sub);
        }

        // 將 User Claims 資訊轉為 Map
        Map<String, Object> claimsMap = buildUserClaimsMap(sub, userClaims);

        // 回傳最終 claims
        return buildClaims(sub, claimMappings, claimsMap);
    }

    private String getValidatedSub(OAuth2Authorization authorization) {
        String sub = authorization.getPrincipalName();

        if (sub == null || sub.trim().isEmpty()) {
            log.error("Subject (sub) is null or empty.");
            throw new IllegalStateException("Cannot generate UserInfo claims because the subject identifier (sub) is missing.");
        }

        return sub;
    }

    private Set<String> getScopes(OidcUserInfoAuthenticationContext context) {
        return context.getAuthorization().getAuthorizedScopes().stream()
                .filter(scope -> !OidcScopes.OPENID.equals(scope))
                .collect(Collectors.toSet());
    }

    private Map<String, Object> buildUserClaimsMap(String sub, List<UserClaim> userClaims) {
        return userClaims.stream()
                .flatMap(claim -> {
                    String claimName = claim.getClaimName();
                    Object claimValue = claim.getValue();

                    // 僅添加是 JsonNode 的部分
                    if (claimValue instanceof JsonNode jsonNode) {
                        try {

                            Object standardJavaObject = objectMapper.treeToValue(jsonNode, Object.class);
                            return Stream.of(Map.entry(claimName, standardJavaObject));

                        // 無法解析不添加
                        } catch (JsonProcessingException e) {
                            log.error("Failed to convert JsonNode to Object for claim '{}' for user {}. Node: {}",
                                    claimName, sub, jsonNode, e);
                            return Stream.empty();
                        }
                    // 不是 JsonNode不添加
                    } else {
                        return Stream.empty();
                    }
                }).collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue,
                        (existingValue, newValue) -> newValue
                ));
    }

    private Map<String, Object> buildSingleClaim(String sub) {
        Map<String, Object> finalClaims = new LinkedHashMap<>();
        finalClaims.put(StringUtil.SUB_CLAIM_NAME, sub);
        return finalClaims;
    }

    private Map<String, Object> buildClaims(String sub, List<ClaimMapping> attributeMappings, Map<String, Object> claimsMap) {
        Map<String, Object> finalClaims = buildSingleClaim(sub);

        attributeMappings.forEach(mapping -> {
            String outputClaimName = mapping.getClaimName();
            String internalClaimName = mapping.getClaimName();

            // 從已經是標準 Object 的 Map 中獲取值
            Object deserializedValue = claimsMap.get(internalClaimName);

            // 僅添加不是 null 的值
            if (deserializedValue != null) {
                finalClaims.put(outputClaimName, deserializedValue);
            }
        });

        return finalClaims;
    }

}
