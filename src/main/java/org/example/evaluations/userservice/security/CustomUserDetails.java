package org.example.evaluations.userservice.security;

import org.example.evaluations.userservice.model.Role;
import org.example.evaluations.userservice.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Class created to implement UserDetails interface from Spring Security.
 * This class maps our User model to Spring Security's UserDetails.
 * It provides necessary user information to Spring Security for authentication and authorization.
 */

public class CustomUserDetails implements UserDetails {

    private User user;

    public CustomUserDetails(User user) {
        this.user = user;
    }
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        List<CustomGrantedAuthority> authorities = new ArrayList<>();

        for(Role role : user.getRoles()) {
            authorities.add(new CustomGrantedAuthority(role));
        }
        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getEmail();
    }
}
