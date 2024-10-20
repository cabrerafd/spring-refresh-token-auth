package com.cabrerafd.security.service;

import com.cabrerafd.security.model.RefreshToken;
import com.cabrerafd.security.model.User;
import com.cabrerafd.security.repository.RefreshTokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtService {

    @Value("${jwt.secret_key}")
    private String SECRET_KEY;

    private final RefreshTokenRepository tokenRepository;

    private final long ACCESS_EXPIRATION = 1000 * 60 * 5;
    private final long REFRESH_EXPIRATION = 1000 * 60 * 60 * 24 * 7;

    private enum TYPE {
        ACCESS,
        REFRESH
    }

    public String extractUsername(String jwt) {
        return extractClaim(jwt, Claims::getSubject);
    }

    public String extractSession(String jwt) {
        return extractClaim(jwt, claims -> claims.get("session")).toString();
    }

    public String generateAccessToken(UserDetails userDetails, String session) {
        return generate(userDetails, session, TYPE.ACCESS.toString(), ACCESS_EXPIRATION);
    }

    public String generateRefreshToken(User user, String session) {
        String refreshToken = generate(user, session, TYPE.REFRESH.toString(), REFRESH_EXPIRATION);

        tokenRepository.save(RefreshToken.builder()
                        .token(refreshToken)
                        .session(session)
                        .valid(true)
                        .user(user)
                .build());

        return refreshToken;
    }

    public String generate(UserDetails userDetails, String session, String type, long expiration) {
        Map<String, Object> claims = Map.of("session", session, "type", type);
        return generate(claims, userDetails, expiration);
    }

    public String generate(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        return Jwts
                .builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey())
                .compact();
    }

    public void invalidateTokens(String session) {
        List<RefreshToken> refreshTokens = tokenRepository.findAllBySessionAndValid(session, true).orElseThrow();

        refreshTokens.forEach(refreshToken -> tokenRepository.save(
                refreshToken.
                        toBuilder().
                        valid(false).
                        build()
        ));
    }

    public boolean isTypeAccess(String jwt) {
        return extractType(jwt).equals(TYPE.ACCESS.toString());
    }

    public boolean isTypeRefresh(String jwt) {
        return extractType(jwt).equals(TYPE.REFRESH.toString());
    }

    public boolean isValid(String jwt, UserDetails userDetails) {
        final String username = extractUsername(jwt);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(jwt);
    }

    private Claims extractAllClaims(String jwt) {
        return Jwts
                .parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(jwt)
                .getPayload();
    }

    private <T> T extractClaim(String jwt, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(jwt);
        return claimsResolver.apply(claims);
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private String extractType(String token) {
        return extractClaim(token, (claims -> claims.get("type"))).toString();
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private boolean isTokenExpired(String jwt) {
        return extractExpiration(jwt).before(new Date());
    }
}
