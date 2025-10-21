package org.example.evaluations.userservice.configs;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

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
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .csrf(csrf -> csrf.disable())
//                .cors(cors -> cors.disable())
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/users/signup", "/users/login", "/users/validate/*").permitAll()
//                        .anyRequest().authenticated()
//                )
//                .formLogin(form -> form.disable())
//                .httpBasic(Customizer.withDefaults())
//                .headers(headers -> headers.frameOptions(frame -> frame.disable()));
//
//        return http.build();
//    }




    /**
     *  START :Adding code for the OAuth2 - Authorization Server
     *  https://docs.spring.io/spring-authorization-server/reference/getting-started.html
     */


    @Bean
    @Order
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                // This ensures this chain only applies to the auth server endpoints
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (authorizationServer) ->
                        authorizationServer.oidc(Customizer.withDefaults())	// Enable OpenID Connect 1.0
                )
                .authorizeHttpRequests((authorize) ->
                        authorize.anyRequest().authenticated()
                )
                // Redirect to the login page when not authenticated from the authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                );

        return http.build();
    }


    @Bean
    @Order
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                // Disable CSRF for API testing (re-enable with tokens later)
                .csrf(csrf -> csrf.disable())

                // Define public vs protected endpoints
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/users/signup", "/users/login", "/users/validate/**").permitAll()
                        .anyRequest().authenticated()
                )
                // Form login handles the redirect to the login page from the authorization server filter chain
                .formLogin(Customizer.withDefaults())

                // Allow basic auth for testing protected API endpoints
                .httpBasic(Customizer.withDefaults());

        return http.build();
    }

    /**
     * We will define our UserDetails class (CustomUserDetails) implementing UserDetails interface,
     * this is to map our User model to Spring Security's UserDetails.
     * We will make a new CustomUserDetails class instead of modifying our own User class to avoid tight-coupling
     * And this is how we should do it for adapting to any external interface/contract
     */
//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails userDetails = User.withDefaultPasswordEncoder()
//        //UserDetails userDetails = User.builder()
//                .username("user")
//                //.password("password")
//                .password(bCryptPasswordEncoder().encode("mypassword")) //Instead of storing plain text password, store encoded password
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(userDetails);
//    }
//    //Default method originally provided by Spring Security tutorial
//    public UserDetailsService userDetailsService() {
//        UserDetails userDetails = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("password")
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(userDetails);
//    }

    /**
     * Define a RegisteredClientRepository bean to manage OAuth2 clients.
     * For managing clients in a production application, consider using a persistent storage mechanism.
     *
     * e.g. For login to any site (e.g. facebook), I am using google as the authorization server
     * similarly here we are creating our own authorization server and registering a client
     * which will be using this authorization server for login
     *
     * To test this hit the URL - http://localhost:8080/login
     * You will get the login page for this authorization server (similar to what you get google login page
     * when you login to any site using google)
     * @return
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("oidc-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
                .postLogoutRedirectUri("http://127.0.0.1:8080/")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(oidcClient);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }
    /**
     *  END :Finished Adding code for the OAuth2 - Authorization Server
     *  https://docs.spring.io/spring-authorization-server/reference/getting-started.html
     */
}
