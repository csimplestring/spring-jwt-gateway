package com.acm.infra.proxy;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractNameValueGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class JWTFilter extends AbstractNameValueGatewayFilterFactory {

    private static final String WWW_AUTH_HEADER = "WWW-Authenticate";
    private static final String X_JWT_SUB_HEADER = "X-jwt-sub";

    private static final Logger logger = LoggerFactory.getLogger(JWTFilter.class);

    @Autowired
    private final JWTVerifier jwtVerifier;

    public JWTFilter(JWTVerifier jwtVerifier) {
        this.jwtVerifier = jwtVerifier;
    }

    @Override
    public GatewayFilter apply(NameValueConfig config) {
        return (exchange, chain) -> {

            try {
                String token = this.extractJWTToken(exchange.getRequest());
                DecodedJWT decodedJWT = this.jwtVerifier.verify(token);

                ServerHttpRequest request = exchange.getRequest().mutate().
                        header(X_JWT_SUB_HEADER, decodedJWT.getSubject()).
                        build();

                return chain.filter(exchange.mutate().request(request).build());

            } catch (JWTVerificationException ex) {

                logger.error(ex.toString());
                return this.onError(exchange, ex.getMessage());
            }
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err)
    {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().add(WWW_AUTH_HEADER, this.formatErrorMsg(err));

        return response.setComplete();
    }

    private String extractJWTToken(ServerHttpRequest request)
    {
        if (!request.getHeaders().containsKey("Authorization")) {
            throw new JWTTokenExtractException("Authorization header is missing");
        }

        List<String> headers = request.getHeaders().get("Authorization");
        if (headers.isEmpty()) {
            throw new JWTTokenExtractException("Authorization header is empty");
        }

        String credential = headers.get(0).trim();
        String[] components = credential.split("\\s");

        if (components.length != 2) {
            throw new JWTTokenExtractException("Malformat Authorization content");
        }

        if (!components[0].equals("Bearer")) {
            throw new JWTTokenExtractException("Bearer is needed");
        }

        return components[1].trim();
    }

    private String formatErrorMsg(String msg)
    {
        return String.format("Bearer realm=\"acm.com\", " +
                "error=\"https://tools.ietf.org/html/rfc7519\", " +
                "error_description=\"%s\" ",  msg);
    }
}
