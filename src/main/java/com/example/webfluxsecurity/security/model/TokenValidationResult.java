package com.example.webfluxsecurity.security.model;

import io.jsonwebtoken.Claims;

public record TokenValidationResult(Claims claims, String token) {
}
