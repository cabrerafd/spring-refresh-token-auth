package com.cabrerafd.security.model;

import com.cabrerafd.security.enums.Role;
import com.cabrerafd.security.helpers.annotations.CustomIdGenerator;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Immutable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
@Builder
@Entity
@Immutable
@NoArgsConstructor(force = true)
@AllArgsConstructor
@Table(name = "_user")
public class User implements UserDetails {

    @Id
    @CustomIdGenerator(prefix = "usr")
    private final String id;
    private final String username;
    private final String password;
    @Enumerated(EnumType.STRING)
    private final Role role;

    @OneToMany(mappedBy = "user")
    private final List<RefreshToken> refreshTokens;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.toString()));
    }

    @Override
    public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return UserDetails.super.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return UserDetails.super.isEnabled();
    }
}
