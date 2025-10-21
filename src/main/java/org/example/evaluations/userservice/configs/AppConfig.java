package org.example.evaluations.userservice.configs;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;


@Configuration
public class AppConfig {

    /**
     * Normally the secret key should be stored in a secure place like environment variable or secret manager (AWS)
     * But for simplicity, we are managing it here as Bean, so that it can be injected wherever needed for both generation and validation
     */

    @Bean
    public SecretKey getSecretKey() {
        //In a real application, use a secure way to manage the secret key

        //    Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        //    MacAlgorithm algorithm = Jwts.SIG.HS256;
        //    SecretKey secretKey = algorithm.key().build();
        //    return SECRET_KEY;

        return Keys.secretKeyFor(SignatureAlgorithm.HS256);
    }


}
