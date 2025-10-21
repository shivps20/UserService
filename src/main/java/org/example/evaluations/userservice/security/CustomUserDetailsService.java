package org.example.evaluations.userservice.security;

import org.example.evaluations.userservice.model.User;
import org.example.evaluations.userservice.repositories.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if(optionalUser.isEmpty()) {
            throw new UsernameNotFoundException("User not found with email: " + email);
        }

        // map roles -> GrantedAuthority while session open
//        List<GrantedAuthority> authorities = optionalUser.get().getRoles().stream()
//                .map(role -> new SimpleGrantedAuthority(role.getValue()))
//                .collect(Collectors.toList());

        return new CustomUserDetails(optionalUser.get());
    }
}
