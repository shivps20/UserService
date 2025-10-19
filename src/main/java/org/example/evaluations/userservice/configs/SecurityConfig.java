package org.example.evaluations.userservice.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 This class extends and customizes Spring Security’s configuration.

 The @EnableWebSecurity annotation tells Spring:
 1. “Activate the web security filters, and allow me to customize how authentication and authorization work.”

 Defining the BCryptPasswordEncoder bean here makes it directly available for use by:
 1.  AuthenticationManager
 2.  UserDetailsService
 3.  DaoAuthenticationProvider
 4.  And any other security-related component

 When to use -  Use this when:
 1.  You are configuring login, authentication, or access rules.
 2.  You have a custom SecurityFilterChain, or AuthenticationProvider setup.
 3.  You want your password encoder to be part of the security configuration (which is best practice).

 @Bean - This annotation tells the Spring to create an instance of this class and store it for usage by other classes
 e.g. Use it for RestTemplate
 */

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
//        httpSecurity.csrf().disable();
//        httpSecurity.cors().disable();
//        httpSecurity.authorizeHttpRequests(
//                authorize -> authorize.anyRequest().permitAll()
//        );
//
//        return httpSecurity.build();
//    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Disable CSRF for local REST/API testing. Re-enable or use tokens in production.
                .csrf(csrf -> csrf.disable())

                // Permit signup/login publicly; protect everything else
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/users/signup", "/users/login", "/h2-console/**").permitAll()
                        .anyRequest().authenticated()
                )

                // Disable the default login form (we use REST)
                .formLogin(form -> form.disable())

                // Optionally enable HTTP Basic for testing protected endpoints
                .httpBasic(Customizer.withDefaults());

        // If using H2 console:
        http.headers(headers -> headers.frameOptions(frame -> frame.disable()));

        return http.build();
    }
}
