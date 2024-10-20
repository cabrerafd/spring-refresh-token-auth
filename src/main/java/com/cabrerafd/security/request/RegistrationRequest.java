package com.cabrerafd.security.request;

import com.cabrerafd.security.enums.Role;

public record RegistrationRequest(String username, String password, Role role) {

}
