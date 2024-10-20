package com.cabrerafd.security.repository;

import com.cabrerafd.security.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {

    Optional<List<RefreshToken>> findAllBySessionAndValid(String session, boolean valid);
    Optional<RefreshToken> findByToken(String refreshToken);
}
