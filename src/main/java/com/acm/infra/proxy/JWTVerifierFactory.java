package com.acm.infra.proxy;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.security.interfaces.RSAPublicKey;

@Component
public class JWTVerifierFactory {

    @Bean
    public JWTVerifier cerate(@Value("${jwt.issuer}") String issuer, @Value("${jwt.audience}") String audience)
            throws JwkException, IOException {

        UrlJwkProvider urlJwkProvider = new UrlJwkProvider(issuer);
        RestTemplate restTemplate = new RestTemplate();

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(restTemplate.getForObject(issuer + "/.well-known/jwks.json", String.class));
        String kid = jsonNode.get("keys").get(0).get("kid").asText();

        Jwk jwk = urlJwkProvider.get(kid);

        return JWT.require(Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null))
                .withIssuer(issuer)
                .withAudience(audience)
                .build();
    }
}
