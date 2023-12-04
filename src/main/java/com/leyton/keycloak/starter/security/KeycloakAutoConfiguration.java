package com.leyton.keycloak.starter.security;

import com.leyton.keycloak.starter.config.coverter.MyJwtGrantedAuthorityConverter;
import com.leyton.keycloak.starter.config.coverter.MyJwtAuthorizationConverter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.CollectionUtils;

import java.util.*;

@AutoConfiguration
@EnableMethodSecurity
@EnableConfigurationProperties(KeycloakProperties.class)
@ConditionalOnProperty(name = "keycloak.enabled", havingValue = "true", matchIfMissing = false)
public class KeycloakAutoConfiguration {

    /**
     * logger
     */
    private final Log log = LogFactory.getLog(getClass());

    /**
     * keycloakProperties
     */
    private final KeycloakProperties keycloakProperties;

    @Autowired
    public KeycloakAutoConfiguration(KeycloakProperties keycloakProperties) {
        this.keycloakProperties = keycloakProperties;
    }

    /**
     *  This method is used to create a SecurityFilterChain Bean which is used to configure the security to use JWT
     * @param http HttpSecurity
     * @return SecurityFilterChain
     * @throws Exception Exception
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

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
                                .jwtAuthenticationConverter(myConverter())
                                .decoder(myDecoder())
        );

        return http.build();
    }

    /**
     * This method is used to create a JwtDecoder Bean which is used to decode (decode & verify using JWK SET URI) the JWT token
     * @return JwtDecoder
     */

    @Bean
    JwtDecoder myDecoder() {
        NimbusJwtDecoder nimbusJwtDecoder = NimbusJwtDecoder.withJwkSetUri(this.keycloakProperties.getJwkSetUri())
                .jwsAlgorithms(this::jwsAlgorithms)
                .build();
        String issuerUri = this.keycloakProperties.getIssuerUri();
        OAuth2TokenValidator<Jwt> defaultValidator = (issuerUri != null)
                ? JwtValidators.createDefaultWithIssuer(issuerUri) : JwtValidators.createDefault();
        nimbusJwtDecoder.setJwtValidator(getValidators(defaultValidator));
        log.info("Decoder created ...");
        return nimbusJwtDecoder;
    }


    /**
     * This method is used to return the JWS algorithms allowed
     * @param signatureAlgorithms Set<SignatureAlgorithm>
     */
    private void jwsAlgorithms(Set<SignatureAlgorithm> signatureAlgorithms) {
        // By default, NimbusJwtDecoder, and hence Resource Server, will only trust and verify tokens using RS256. if you want to use other algorithms, you need to configure them explicitly using the jwsAlgorithms method.
        for (String algorithm : this.keycloakProperties.getJwsAlgorithms()) {
            signatureAlgorithms.add(SignatureAlgorithm.from(algorithm));
        }
    }

    /**
     * This method is used to return the OAuth2TokenValidator<Jwt> which is used to validate the JWT token(for validating jwt claims like issuer, audience, time ,  etc)
     * @param defaultValidator OAuth2TokenValidator<Jwt>
     * @return OAuth2TokenValidator<Jwt>
     */
    private OAuth2TokenValidator<Jwt> getValidators(OAuth2TokenValidator<Jwt> defaultValidator) {
        List<String> audiences = this.keycloakProperties.getAudiences();
        // in many cases the audience is not considered to be validated, so we need to check for null
        if (CollectionUtils.isEmpty(audiences)) {
            return defaultValidator;
        }
         // here we can add more validators if needed (custom validators also can be added)
         // most iss aud and time validations are done by default validator
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(defaultValidator);
        validators.add(new JwtClaimValidator<List<String>>(JwtClaimNames.AUD,
                (aud) -> aud != null && !Collections.disjoint(aud, audiences)));
        return new DelegatingOAuth2TokenValidator<>(validators);
    }


    /**
     * This method is used to create a MyJwtAuthorizationConverter Bean which is used to convert the JWT authorities claim to Spring Security GrantedAuthority list which is used for authorization
     * @return MyJwtAuthorizationConverter
     */
    public MyJwtAuthorizationConverter myConverter() {
        Converter<Jwt, Collection<GrantedAuthority>> myJwtGrantedAuthorityConverter = new MyJwtGrantedAuthorityConverter(keycloakProperties);
        return new MyJwtAuthorizationConverter(myJwtGrantedAuthorityConverter);
    }
}

