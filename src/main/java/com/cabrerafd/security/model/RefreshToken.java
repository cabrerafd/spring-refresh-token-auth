package com.cabrerafd.security.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder(toBuilder = true)
@Entity
@NoArgsConstructor(force = true)
@AllArgsConstructor
public class RefreshToken {

    @Id
    @Column(length = 1000)
    private final String token;

    private final boolean valid;

    private final String session;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private final User user;

}
