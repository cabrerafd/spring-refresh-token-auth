package com.cabrerafd.security.service;

import com.cabrerafd.security.enums.Role;
import com.cabrerafd.security.exception.InvalidRefreshToken;
import com.cabrerafd.security.model.RefreshToken;
import com.cabrerafd.security.model.User;
import com.cabrerafd.security.repository.RefreshTokenRepository;
import com.cabrerafd.security.repository.UserRepository;
import com.cabrerafd.security.request.LoginRequest;
import com.cabrerafd.security.request.RefreshTokenRequest;
import com.cabrerafd.security.request.RegistrationRequest;
import com.cabrerafd.security.response.AuthenticationResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository tokenRepository;
    private final UserRepository userRepository;

    public AuthenticationResponse register(RegistrationRequest request) {
        User user = userRepository.save(User.builder()
                .username(request.username())
                .password(passwordEncoder.encode(request.password()))
                .role(Role.USER)
                .build());

        final String session = UUID.randomUUID().toString();
        String accessToken = jwtService.generateAccessToken(user, session);
        String refreshToken = jwtService.generateRefreshToken(user, session);
        return new AuthenticationResponse(accessToken, refreshToken);
    }

    public AuthenticationResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    request.username(),
                    request.password()
                )
        );

        User user = userRepository.findByUsername(request.username())
                .orElseThrow();

        final String session = UUID.randomUUID().toString();
        String accessToken = jwtService.generateAccessToken(user, session);
        String refreshToken = jwtService.generateRefreshToken(user, session);

        return new AuthenticationResponse(accessToken, refreshToken);
    }

    public AuthenticationResponse refreshToken (RefreshTokenRequest request) {
        final String jwt = request.token();

        if (!jwtService.isTypeRefresh(jwt)) throw new InvalidRefreshToken();

        final String session = jwtService.extractSession(jwt);
        final String username = jwtService.extractUsername(jwt);

        User user = userRepository.findByUsername(username)
                .orElseThrow(InvalidRefreshToken::new);

        if (!jwtService.isValid(jwt, user)) {
            jwtService.invalidateTokens(session);
            throw new InvalidRefreshToken();
        };

        RefreshToken token = tokenRepository.findByToken(jwt)
                .orElseThrow(() -> {
                    jwtService.invalidateTokens(session);
                    return new InvalidRefreshToken();
                });

        if (!token.isValid()) {
            jwtService.invalidateTokens(session);
            throw new InvalidRefreshToken();
        }

        jwtService.invalidateTokens(session);
        String accessToken = jwtService.generateAccessToken(user, session);
        String refreshToken = jwtService.generateRefreshToken(user, session);

        return new AuthenticationResponse(accessToken, refreshToken);
    }
}
