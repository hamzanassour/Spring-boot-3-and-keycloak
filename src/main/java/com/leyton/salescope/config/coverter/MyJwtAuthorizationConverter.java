package com.leyton.salescope.config.coverter;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;

public class MyJwtAuthorizationConverter implements Converter<Jwt, AbstractAuthenticationToken> {


    private Converter<Jwt, Collection<GrantedAuthority>> myJwtGrantedAuthorityConverter = new MyJwtGrantedAuthorityConverter();

    private String principalClaimName = "preferred_username";



    @Override
    public AbstractAuthenticationToken convert(Jwt source) {
        String principalClaimValue = source.getClaimAsString(this.principalClaimName);
        return new JwtAuthenticationToken(source , myJwtGrantedAuthorityConverter.convert(source) , principalClaimValue );
    }
}
