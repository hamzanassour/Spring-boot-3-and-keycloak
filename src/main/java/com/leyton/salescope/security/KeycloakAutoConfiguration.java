package com.leyton.salescope.security;

import com.leyton.salescope.config.coverter.MyJwtAuthorizationConverter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

@AutoConfiguration
@EnableMethodSecurity
@EnableConfigurationProperties(KeycloakProperties.class)
public class KeycloakAutoConfiguration {

    private final Log log = LogFactory.getLog(getClass());

    private final KeycloakProperties keycloakProperties;

    @Autowired
    public KeycloakAutoConfiguration(KeycloakProperties keycloakProperties) {
        this.keycloakProperties = keycloakProperties;
    }

    @Bean
    @ConditionalOnProperty(name = "keycloak.enabled", havingValue = "true", matchIfMissing = false)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {


        log.warn("AutoConfiguration applied successfully");

        http.authorizeHttpRequests(
                request ->
                        request.anyRequest().authenticated()
        );

        http.sessionManagement(
                session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );

        http.oauth2ResourceServer(
                oauth2ResourceServer ->
                        oauth2ResourceServer
                                .jwt()
                                .jwtAuthenticationConverter(new MyJwtAuthorizationConverter())
                                .decoder(myDecoder())
        );

        return http.build();
    }



    @Bean
    @ConditionalOnProperty(name = "keycloak.enabled", havingValue = "true", matchIfMissing = false)
    JwtDecoder myDecoder() {
        log.warn("craeting  decoder");
        NimbusJwtDecoder nimbusJwtDecoder = NimbusJwtDecoder.withJwkSetUri(this.keycloakProperties.getJwkSetUri())
                .jwsAlgorithms(this::jwsAlgorithms)
                .build();
        String issuerUri = this.keycloakProperties.getIssuerUri();
        OAuth2TokenValidator<Jwt> defaultValidator = (issuerUri != null)
                ? JwtValidators.createDefaultWithIssuer(issuerUri) : JwtValidators.createDefault();
        nimbusJwtDecoder.setJwtValidator(getValidators(defaultValidator));
        return nimbusJwtDecoder;
    }


    private void jwsAlgorithms(Set<SignatureAlgorithm> signatureAlgorithms) {
        for (String algorithm : this.keycloakProperties.getJwsAlgorithms()) {
            signatureAlgorithms.add(SignatureAlgorithm.from(algorithm));
        }
    }

    private OAuth2TokenValidator<Jwt> getValidators(OAuth2TokenValidator<Jwt> defaultValidator) {
        List<String> audiences = this.keycloakProperties.getAudiences();
        if (CollectionUtils.isEmpty(audiences)) {
            return defaultValidator;
        }
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(defaultValidator);
        validators.add(new JwtClaimValidator<List<String>>(JwtClaimNames.AUD,
                (aud) -> aud != null && !Collections.disjoint(aud, audiences)));
        return new DelegatingOAuth2TokenValidator<>(validators);
    }
}

