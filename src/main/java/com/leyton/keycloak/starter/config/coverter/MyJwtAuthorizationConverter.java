package com.leyton.keycloak.starter.config.coverter;

import lombok.AllArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;


@AllArgsConstructor
public class MyJwtAuthorizationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private Converter<Jwt, Collection<GrantedAuthority>> myJwtGrantedAuthorityConverter;



    @Override
    public AbstractAuthenticationToken convert(Jwt source) {
        String principalClaimValue = source.getClaimAsString(JwtClaimNames.SUB);
        return new JwtAuthenticationToken(source , myJwtGrantedAuthorityConverter.convert(source) , principalClaimValue);
    }
}
