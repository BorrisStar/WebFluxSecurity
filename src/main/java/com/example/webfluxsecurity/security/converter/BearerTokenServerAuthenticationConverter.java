package com.example.webfluxsecurity.security.converter;

import com.example.webfluxsecurity.security.authentication.AuthenticationProvider;
import com.example.webfluxsecurity.security.service.JwtTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@RequiredArgsConstructor
public class BearerTokenServerAuthenticationConverter implements ServerAuthenticationConverter {
    private final AuthenticationProvider authenticationProvider;
    private final JwtTokenService jwtTokenService;

    private final String BEARER_PREFIX = "Bearer_";

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        return extractHeader(exchange)
                .flatMap(authValue -> Mono.justOrEmpty(authValue.substring(BEARER_PREFIX.length())))
                .flatMap(jwtTokenService::validateToken)
                .flatMap(authenticationProvider::create);
    }

    private Mono<String> extractHeader(ServerWebExchange exchange) {
        return Mono.justOrEmpty(exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION));
    }
}
