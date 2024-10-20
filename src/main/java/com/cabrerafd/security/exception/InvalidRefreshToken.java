package com.cabrerafd.security.exception;

import lombok.Getter;

@Getter
public class InvalidRefreshToken extends RuntimeException{

    private final String message = "Invalid token";

}
