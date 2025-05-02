package com.arplanets.auth.test;

import com.arplanets.auth.component.UserPoolContext;
import com.arplanets.auth.component.UserPoolContextHolder;
import com.arplanets.auth.model.po.domain.ClaimMapping;
import com.arplanets.auth.model.po.domain.ClientRegistrationMapping;
import com.arplanets.auth.model.po.domain.UserPool;
import com.arplanets.auth.repository.ClientRegistrationMappingRepository;
import com.arplanets.auth.repository.ClaimMappingRepository;
import com.arplanets.auth.repository.UserPoolRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.*;


@Component
@RequiredArgsConstructor
@Slf4j
public class InitialDataLoader implements CommandLineRunner {

    private final RegisteredClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;
    private final CustomClientRegistrationRepository clientRegistrationRepository;
    private final ClientRegistrationMappingRepository clientRegistrationMappingRepository;
    private final ClaimMappingRepository claimMappingRepository;
    private final UserPoolRepository userPoolRepository;
    private final ObjectMapper objectMapper;

    @Override
    public void run(String... args) {
        if (userPoolRepository.findById("pool1") == null) {

            Set<String> scopes = new HashSet<>();
            scopes.add("openid");
            scopes.add("profile");
            scopes.add("email");

            JWKSet jwkSet = jwkSet();
            String jwkSetJson;
            try {
                jwkSetJson = objectMapper.writeValueAsString(jwkSet.toJSONObject(false));
            } catch (Exception e) {
                throw new RuntimeException("Failed to serialize JWKSet to JSON", e);
            }


            UserPool userPool = UserPool.builder()
                    .userPoolId("pool1")
                    .poolName("pool1")
                    .scopes(scopes)
                    .jwkSet(jwkSetJson)
                    .build();

            userPoolRepository.save(userPool);
        }

        UserPoolContext userPoolContext = UserPoolContext.builder()
                .userPoolId("pool1")
                .build();

        UserPoolContextHolder.setContext(userPoolContext);
        if (clientRepository.findByClientId("third-party-app") == null) {
            RegisteredClient thirdPartyApplication = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("third-party-app")
                    .clientIdIssuedAt(Instant.now())  // 确保设置这个字段
                    .clientSecret(passwordEncoder.encode("your-client-secret"))
                    .clientName("Third Party Application")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("http://localhost:8081/login/oauth2/code/custom-idp")
                    .redirectUri("http://localhost:8081/authorized")
                    .postLogoutRedirectUri("http://localhost:8081/logout-success")
                    .postLogoutRedirectUri("http://localhost:8081/logout")
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .scope(OidcScopes.EMAIL)
                    .scope("api.read")
                    .scope("api.write")
                    .clientSettings(ClientSettings.builder()
                            // 需要同意頁面
                            .requireAuthorizationConsent(true)
                            .build())
                    .tokenSettings(TokenSettings.builder()
                            // access token 存活時間 30 分鐘
                            .accessTokenTimeToLive(Duration.ofMinutes(30))
                            // refresh token 存活時間 7 天
                            .refreshTokenTimeToLive(Duration.ofDays(7))
                            // 每次刷新 token 都發放新的 token
                            .reuseRefreshTokens(false)
                            .build())
                    .build();

            clientRepository.save(thirdPartyApplication);
        }

        if (!clientRegistrationRepository.existsById("6e248bda-be14-4410-9230-f3de62c44375")) {
            Set<String> scopes = new HashSet<>();
            scopes.add(OidcScopes.OPENID);
            scopes.add(OidcScopes.EMAIL);
            scopes.add(OidcScopes.PROFILE);

            String registrationId = UUID.randomUUID().toString();

            ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(registrationId)
                    .clientName("keycloak")
                    .clientId("third-party-app-keycloak")
                    .clientSecret("third-party-app-keycloak-secret")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .issuerUri("http://localhost:8080/realms/app-realm")
                    .redirectUri("http://localhost:9000/login/oauth2/code/" + registrationId)
                    .scope(scopes)
                    .authorizationUri("http://localhost:9000/login/oauth2/authorize")
                    .tokenUri("http://localhost:9000/oauth2/token")
                    .userInfoUri("http://localhost:9000/userinfo")
                    .jwkSetUri("http://localhost:9000/login/oauth2/authorize")
                    .userNameAttributeName("sub")
                    .build();

            ((CustomClientRegistrationRepository) clientRegistrationRepository).insert(clientRegistration);
        }


        if (clientRegistrationMappingRepository.findByClientId("third-party-app") == null) {
            ClientRegistrationMapping clientRegistrationMapping = ClientRegistrationMapping.builder()
                    .clientId("third-party-app")
                    .registrationId("6e248bda-be14-4410-9230-f3de62c44375")
                    .build();

            clientRegistrationMappingRepository.save(clientRegistrationMapping);
        }

        List<ClaimMapping> claimMappingList = new ArrayList<>();



        ClaimMapping email = ClaimMapping.builder()
                .registrationId("6e248bda-be14-4410-9230-f3de62c44375")
                .claimName("test_email")
                .idpClaimName("email")
                .scope(OidcScopes.EMAIL)
                .build();

        ClaimMapping emailVerified = ClaimMapping.builder()
                .registrationId("6e248bda-be14-4410-9230-f3de62c44375")
                .claimName("test_email_verified")
                .idpClaimName("email_verified")
                .scope(OidcScopes.EMAIL)
                .build();

        ClaimMapping name = ClaimMapping.builder()
                .registrationId("6e248bda-be14-4410-9230-f3de62c44375")
                .claimName("test_name")
                .idpClaimName("name")
                .scope(OidcScopes.PROFILE)
                .build();

        claimMappingList.add(email);
        claimMappingList.add(emailVerified);
        claimMappingList.add(name);

        claimMappingRepository.saveAll(claimMappingList);

        UserPoolContextHolder.clearContext();


    }

    public JWKSet jwkSet() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        return  new JWKSet(rsaKey);
    }

    private static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }


}
