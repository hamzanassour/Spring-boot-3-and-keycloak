package com.leyton.keycloak.starter.config.coverter;

import com.leyton.keycloak.starter.security.KeycloakProperties;
import lombok.AllArgsConstructor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import java.util.*;


@AllArgsConstructor
public class MyJwtGrantedAuthorityConverter implements Converter<Jwt, Collection<GrantedAuthority>> {


    private final KeycloakProperties keycloakProperties;

    private static final String DEFAULT_ROLE_PREFIX = "ROLE_";

    private static final String RESOURCE_ACCESS_CLAIM = "resource_access";

    private static final String CLIENT_ROLES = "roles";

    private final Log log = LogFactory.getLog(getClass());

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        for (String authority : getAuthorities(jwt)) {
            grantedAuthorities.add(new SimpleGrantedAuthority(DEFAULT_ROLE_PREFIX + authority));
        }
        return grantedAuthorities;
    }

    private Collection<String> getAuthorities(Jwt jwt) {
        Map<String , Object> resourceAccess;
        Map<String , Object> clientName;
        Collection<String> clientRoles;

        if (jwt.getClaim(RESOURCE_ACCESS_CLAIM) == null) {
            log.warn("JWT does not contain the " + RESOURCE_ACCESS_CLAIM + "claim.");
            return Collections.emptyList();
        }
        // extracting resource_access claim
        resourceAccess = jwt.getClaim(RESOURCE_ACCESS_CLAIM);

        if (resourceAccess.get(keycloakProperties.getClientName()) == null) {
            log.warn("JWT does not contain the " + keycloakProperties.getClientName() + " claim.");
            return Collections.emptyList();
        }

        clientName = (Map<String, Object>) resourceAccess.get(keycloakProperties.getClientName());

        if (clientName.get(CLIENT_ROLES) == null){
            log.warn("JWT does not contain the " + CLIENT_ROLES + " claim.");
            return Collections.emptyList();
        }
        // extracting client-roles from the client clause
        clientRoles = (Collection<String>) clientName.get(CLIENT_ROLES);
        return clientRoles ;
    }

}
