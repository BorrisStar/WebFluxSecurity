package com.example.webfluxsecurity.exception;


import org.springframework.security.core.AuthenticationException;

public class AuthException extends AuthenticationException {
    protected String errorCode;

    public AuthException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }
}
