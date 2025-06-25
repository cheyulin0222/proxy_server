package com.arplanets.auth.config;

import com.arplanets.auth.component.spring.oidc.*;
import com.arplanets.auth.filter.RegistrationIdValidationFilter;
import com.arplanets.auth.filter.UserPoolValidationFilter;
import com.arplanets.auth.log.LogContext;
import com.arplanets.auth.log.LoggingFilter;
import com.arplanets.auth.repository.persistence.RegisteredClientPersistentRepository;
import com.arplanets.auth.service.inmemory.InMemoryClientRegistrationService;
import com.arplanets.auth.service.inmemory.UserPoolInfoSource;
import com.arplanets.auth.service.persistence.impl.AuthActivityService;
import com.arplanets.auth.service.persistence.impl.TokenService;
import com.arplanets.auth.service.ProviderLogoutService;
import com.arplanets.auth.utils.StringUtil;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.Module;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.util.matcher.*;

import java.util.List;


@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {

    @Value("${aws.cloudwatch.log-stream-prefix}")
    private String logStreamPrefix;

    /**
     * 處理 OIDC 端點請求
     */
    @Bean
    @Order(1)
    public SecurityFilterChain oidcSecurityFilterChain(
            HttpSecurity http,
            TokenService tokenService,
            AuthActivityService authActivityService,
            OAuth2AuthorizationService authorizationService,
            UserInfoMapper userInfoMapper,
            ObjectMapper objectMapper,
            UserPoolInfoSource userPoolInfoSource,
            LogContext logContext,
            ClientRegistrationRepository clientRegistrationRepository,
            ProviderLogoutService providerLogoutService
    ) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint
                        .authorizationResponseHandler(new AuthorizationSuccessHandlerImpl(authActivityService, authorizationService)))
                .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                        .accessTokenResponseHandler(new TokenResponseHandlerImpl(tokenService, authorizationService)))
                .tokenRevocationEndpoint(revokeEndpoint -> revokeEndpoint
                        .revocationResponseHandler(new RevocationResponseHandlerImpl(authorizationService)))
                .oidc(oidc -> oidc
                        .providerConfigurationEndpoint(Customizer.withDefaults())
                        .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
                                .userInfoMapper(userInfoMapper))
                        .logoutEndpoint(logoutEndpoint -> logoutEndpoint
                                .logoutResponseHandler(new LogoutSuccessHandlerImpl(authActivityService, authorizationService, clientRegistrationRepository, providerLogoutService))));
        http.exceptionHandling(exceptions -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint(StringUtil.LOGIN_PATH),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        ))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .addFilterBefore(new LoggingFilter(logStreamPrefix), WebAsyncManagerIntegrationFilter.class)
                .addFilterAfter(new UserPoolValidationFilter(userPoolInfoSource, objectMapper), HeaderWriterFilter.class);

        return http.build();

    }

    /**
     * 處理 OAuth2 請求
     */
    @Bean
    @Order(2)
    public SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http, InMemoryClientRegistrationService inMemoryClientRegistrationService, RegisteredClientPersistentRepository registeredClientPersistentRepository) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(StringUtil.LOGIN_PATH, StringUtil.FAVICON_PATH, StringUtil.ERROR_PATH).permitAll()
                        .anyRequest().authenticated())
            // 當請求來源於瀏覽器，(且無 Authorization: Bearer <TOKEN>)時走
            .oauth2Login(oauth2 -> oauth2
                    .loginPage(StringUtil.LOGIN_PATH))
            .cors(Customizer.withDefaults())
            .addFilterBefore(new RegistrationIdValidationFilter(inMemoryClientRegistrationService, registeredClientPersistentRepository), OAuth2AuthorizationRequestRedirectFilter.class);

        return http.build();
    }

    /**
     * JWT 解碼器
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * 設定多個 UserPool
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .multipleIssuersAllowed(true)
                .build();
    }

    /**
     * 密碼加密器
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * oauth2_authorization_consent 資料表的讀取和寫入
     */
    @Bean
    public OAuth2AuthorizationConsentService auth2AuthorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository clientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, clientRepository);
    }

    /**
     * oauth2_authorization 資料表的寫入和讀取，因為客製化了 User ， 所以要添加序列化和反序列化方式
     */
    @Bean
    public OAuth2AuthorizationService auth2AuthorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository clientRepository) {

        JdbcOAuth2AuthorizationService authorizationService = new JdbcOAuth2AuthorizationService(jdbcTemplate, clientRepository);

        ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();

        List<Module> securityModules  = SecurityJackson2Modules.getModules(classLoader);

        // 一定要 new 一個，用注入的會有問題!!!
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModules(securityModules);
        objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        objectMapper.addMixIn(OidcUserImpl.class, OidcUserImplWrapperMixin.class);
        objectMapper.addMixIn(com.nimbusds.jose.shaded.gson.internal.LinkedTreeMap.class, LinkedTreeMapMixIn.class);

        // 2. 配置 RowMapper (用於讀取/反序列化)
        JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper rowMapper =
                new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(clientRepository);

        rowMapper.setObjectMapper(objectMapper);

        // 5. 將配置好的 RowMapper 設置回 authorizationService
        authorizationService.setAuthorizationRowMapper(rowMapper);

        // 3. *** 配置 ParametersMapper (用於寫入/序列化) ***
        JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper parametersMapper =
                new JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper();
        parametersMapper.setObjectMapper(objectMapper);
        authorizationService.setAuthorizationParametersMapper(parametersMapper);

        return authorizationService;
    }

}
