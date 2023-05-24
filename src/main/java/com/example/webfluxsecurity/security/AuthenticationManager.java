package com.example.webfluxsecurity.security;

import com.example.webfluxsecurity.entity.UserEntity;
import com.example.webfluxsecurity.exception.UnauthorizedException;
import com.example.webfluxsecurity.repository.UserRepository;
import com.example.webfluxsecurity.security.model.CustomPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class AuthenticationManager implements ReactiveAuthenticationManager {
    private final UserRepository userRepository;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        CustomPrincipal principal = (CustomPrincipal) authentication.getPrincipal();

        return userRepository.findById(principal.getId())
                .filter(UserEntity::isEnabled)
                .switchIfEmpty(Mono.error(new UnauthorizedException("User disabled!")))
                .map(user -> authentication);
    }
}
