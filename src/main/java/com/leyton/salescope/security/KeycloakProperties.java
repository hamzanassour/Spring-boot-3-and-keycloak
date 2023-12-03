package com.leyton.salescope.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@ConfigurationProperties(prefix = "keycloak")
@Getter
@Setter
public class KeycloakProperties {

    private boolean enabled;

    private String issuerUri;

    private String jwkSetUri;

    private List<String> jwsAlgorithms = Arrays.asList("RS256");

    private List<String> audiences = new ArrayList<>();
}
