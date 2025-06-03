package com.arplanets.auth.config;

import com.arplanets.auth.component.spring.oidc.AuthorizationSuccessHandlerImpl;
import com.arplanets.auth.component.spring.oidc.LogoutSuccessHandlerImpl;
import com.arplanets.auth.component.spring.oidc.TokenResponseHandlerImpl;
import com.arplanets.auth.component.spring.oidc.UserInfoMapper;
import com.arplanets.auth.filter.RegistrationIdValidationFilter;
import com.arplanets.auth.filter.UserPoolValidationFilter;
import com.arplanets.auth.log.LogContext;
import com.arplanets.auth.log.LoggingFilter;
import com.arplanets.auth.component.spring.oidc.OidcUserImpl;
import com.arplanets.auth.repository.RegisteredClientPersistentRepository;
import com.arplanets.auth.service.*;
import com.arplanets.auth.service.impl.ClientRegistrationService;
import com.arplanets.auth.utils.StringUtil;
import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
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
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
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

import java.io.IOException;
import java.util.List;
import java.util.Set;


@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {

    /**
     * 處理 OIDC 端點
     */
    @Bean
    @Order(1)
    public SecurityFilterChain oidcSecurityFilterChain(
            HttpSecurity http,
            TokenService tokenService,
            OAuth2AuthorizationService oAuth2AuthorizationService,
            AuthActivityService authActivityService,
            OAuth2AuthorizationService authorizationService,
            UserInfoMapper userInfoMapper,
            ObjectMapper objectMapper,
            UserPoolInfoSource userPoolInfoSource,
            LogContext logContext
    ) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint
                        .authorizationResponseHandler(new AuthorizationSuccessHandlerImpl(authActivityService, authorizationService)))
                .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                        .accessTokenResponseHandler(new TokenResponseHandlerImpl(tokenService, oAuth2AuthorizationService)))
                .oidc(oidc -> oidc
                        .providerConfigurationEndpoint(Customizer.withDefaults())
                        .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
                                .userInfoMapper(userInfoMapper))
                        .logoutEndpoint(logoutEndpoint -> logoutEndpoint
                                .logoutResponseHandler(new LogoutSuccessHandlerImpl(authActivityService, authorizationService))));
        http.exceptionHandling(exceptions -> exceptions
                .defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint(StringUtil.LOGIN_PATH),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                ))
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
            .csrf(AbstractHttpConfigurer::disable)
            .addFilterBefore(new LoggingFilter(logContext), WebAsyncManagerIntegrationFilter.class)
            .addFilterAfter(new UserPoolValidationFilter(userPoolInfoSource, objectMapper), HeaderWriterFilter.class);

        return http.build();

    }

    /**
     * 處理 OAuth2
     */
    @Bean
    @Order(2)
    public SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http, ClientRegistrationService clientRegistrationService, RegisteredClientPersistentRepository registeredClientPersistentRepository) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(StringUtil.LOGIN_PATH, StringUtil.FAVICON_PATH, StringUtil.ERROR_PATH).permitAll()
                        .anyRequest().authenticated())
            // 當請求來源於瀏覽器，(且無 Authorization: Bearer <TOKEN>)時走
            .oauth2Login(oauth2 -> oauth2
                    .loginPage(StringUtil.LOGIN_PATH))
            .addFilterBefore(new RegistrationIdValidationFilter(clientRegistrationService, registeredClientPersistentRepository), OAuth2AuthorizationRequestRedirectFilter.class);

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .multipleIssuersAllowed(true)
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public OAuth2AuthorizationService auth2AuthorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository clientRepository, ObjectMapper objectMapper) {
        JdbcOAuth2AuthorizationService authorizationService = new JdbcOAuth2AuthorizationService(jdbcTemplate, clientRepository);

        ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();

        List<Module> securityModules  = SecurityJackson2Modules.getModules(classLoader);
        objectMapper.registerModules(securityModules);

        objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());

        objectMapper.addMixIn(OidcUserImpl.class, CustomOidcUserWrapperMixin.class);

        // 2. 配置 RowMapper (用於讀取/反序列化)
        JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper rowMapper =
                new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(clientRepository);


        rowMapper.setObjectMapper(objectMapper);

        // 5. 將配置好的 RowMapper 設置回 authorizationService
        authorizationService.setAuthorizationRowMapper(rowMapper);

        // 3. *** 配置 ParametersMapper (用於寫入/序列化) *** <--- 這是新增的關鍵步驟
        JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper parametersMapper =
                new JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper();
        parametersMapper.setObjectMapper(objectMapper); // <--- 將同一個 ObjectMapper 設置給 ParametersMapper
        authorizationService.setAuthorizationParametersMapper(parametersMapper);

        return authorizationService;
    }


    @Bean
    public OAuth2AuthorizationConsentService auth2AuthorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository clientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, clientRepository);
    }


    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
    @JsonAutoDetect(
            fieldVisibility = JsonAutoDetect.Visibility.ANY,
            getterVisibility = JsonAutoDetect.Visibility.NONE,
            isGetterVisibility = JsonAutoDetect.Visibility.NONE
    )
    @JsonIgnoreProperties(ignoreUnknown = true)
    abstract static class CustomOidcUserWrapperMixin {

        @JsonProperty("customUserName")
        private String customUserName;

        @JsonProperty("oidcUser")
        private OidcUser oidcUser;

        @JsonCreator
        CustomOidcUserWrapperMixin(
                @JsonProperty("oidcUser") OidcUser oidcUser,
                @JsonProperty("customUserName") String customUserName) {
        }
    }

}
