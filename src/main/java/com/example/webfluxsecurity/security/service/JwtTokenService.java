package com.example.webfluxsecurity.security.service;

import com.example.webfluxsecurity.entity.UserEntity;
import com.example.webfluxsecurity.exception.AuthException;
import com.example.webfluxsecurity.exception.UnauthorizedException;
import com.example.webfluxsecurity.repository.UserRepository;
import com.example.webfluxsecurity.security.model.TokenDetails;
import com.example.webfluxsecurity.security.model.TokenValidationResult;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.security.Key;
import java.util.Date;

@Component
public class JwtTokenService {
    @Value("${jwt.expiration}")
    private Integer expirationInMilliSeconds;
    @Value("${jwt.issuer}")
    private String issuer;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private final Key key;

    public JwtTokenService(@Value("${jwt.secret}") String secret, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
    }

    private TokenDetails generateToken(UserEntity user) {
        Date now = new Date();
        Date expirationDate = new Date(now.getTime() + expirationInMilliSeconds);
        String subject = String.valueOf(user.getId());

        Claims claims = Jwts.claims().setSubject(subject);
        claims.put("role", user.getRole().name());
        claims.put("username", user.getUsername());

        String token = Jwts.builder()
                .setClaims(claims)
                .setIssuer(issuer)
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(expirationDate)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        return TokenDetails.builder()
                .userId(user.getId())
                .token(token)
                .issuedAt(now)
                .expiresAt(expirationDate)
                .build();
    }

    public Mono<TokenDetails> authenticate(String username, String password) {
        return userRepository.findByUsername(username)
                .flatMap(user -> {
                            if (!user.isEnabled()) {
                                return Mono.error(new AuthException("User disabled!", "USER_DISABLED"));
                            }
                            if (!passwordEncoder.matches(password, user.getPassword())) {
                                return Mono.error(new AuthException("Password incorrect!", "PASSWORD_INCORRECT"));
                            }
                            TokenDetails tokenDetails = generateToken(user);
                            return Mono.just(tokenDetails);
                        }
                ).switchIfEmpty(Mono.error(new AuthException("Invalid username!", "INVALID_USERNAME")));
    }

    public Mono<TokenValidationResult> validateToken(String token) {
        try {
            Claims claims = getClaimsJws(token);

            if (claims.getExpiration().before(new Date())) {
                throw new RuntimeException("JWT token is expired!");
            }

            TokenValidationResult tokenValidationResult = new TokenValidationResult(claims, token);

            return Mono.just(tokenValidationResult)
                    .onErrorResume(ex -> Mono.error(new UnauthorizedException("User unauthorized!")));

        } catch (JwtException | IllegalArgumentException e) {
            throw new AuthException("JWT token is invalid!", "TOKEN_INVALID");
        }

    }

    private Claims getClaimsJws(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }
}
