package com.cabrerafd.security.response;

public record AuthenticationResponse(String accessToken, String refreshToken) {
}
