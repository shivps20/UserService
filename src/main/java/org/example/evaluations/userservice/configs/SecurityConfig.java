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

    /**
     * Configure security filter chain as we are using Security dependency and by default all endpoints are made secure.
     * If the SecurityFilterChain bean is not defined, Spring Security may apply default security settings that could restrict access to your application’s endpoints
     * i.e. it will not allow unauthenticated access to any endpoint, which may not be the intended behavior for your application.
     * e.g. APIs like /users/signup and /users/login should be publicly accessible without authentication.
     *
     * Spring Security applies a chain of servlet filters to every request; a SecurityFilterChain bean tells Spring how to build and configure that chain for your application.
     * Since WebSecurityConfigurerAdapter was deprecated, providing a @Bean of type SecurityFilterChain is the recommended way to customize HttpSecurity (authorize rules, CSRF, CORS, login form, basic auth, headers, etc.).
     * Benefits:
     * 1. Explicitly registers your HTTP security rules (which endpoints are public vs protected).
     * 2. Lets you disable/enable features (CSRF, form login, frame options for H2) required for your use case.
     * 3. Supports multiple filter chains with ordering when you need different rules for different request matchers.
     * 4. Integrates with other security beans (e.g., PasswordEncoder, AuthenticationProvider, AuthenticationManager).
     *
     * Without a configured SecurityFilterChain, Spring will either apply default auto-configuration (which may lock endpoints) or won’t reflect your intended security behavior.
     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                // Disable CSRF for local REST/API testing. Re-enable or use tokens in production.
//                .csrf(csrf -> csrf.disable())
//
//                // Permit signup/login publicly; protect everything else
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/users/signup", "/users/login", "/users/validate/*").permitAll()
//                        .anyRequest().authenticated()
//                )
//
//                // Disable the default login form (we use REST)
//                .formLogin(form -> form.disable())
//
//                // Optionally enable HTTP Basic for testing protected endpoints
//                .httpBasic(Customizer.withDefaults());
//
//        // If using H2 console:
//        http.headers(headers -> headers.frameOptions(frame -> frame.disable()));
//
//        return http.build();
//    }

// java
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/users/signup", "/users/login", "/users/validate/*").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form.disable())
                .httpBasic(Customizer.withDefaults())
                .headers(headers -> headers.frameOptions(frame -> frame.disable()));

        return http.build();
    }

}
