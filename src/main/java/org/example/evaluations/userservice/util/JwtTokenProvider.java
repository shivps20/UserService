package org.example.evaluations.userservice.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.Map;

@Component
public class JwtTokenProvider {
    private static final long EXPIRATION_TIME = 1000 * 60 * 60; // 1 hour
    private static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);


    /**
     * To generate a JWT token, you typically need to include the following 3 things:
     *  1. Header
     *  2. Payload - User Attributes
     *  3. Signature - Algorithm + Secret Key
     */
    public static String generateToken(String email, String role) {
        long now = System.currentTimeMillis();
        Date issuedAt = new Date(now);
        Date expiry = new Date(now + EXPIRATION_TIME);

        Map<String, Object> claims = Map.of(
                "email", email,
                "role", role
        );

        return Jwts.builder()   //Creates a new JWT builder instance.
                .setSubject(email)  //Sets the subject (sub) claim of the JWT, typically the user identifier.
                .addClaims(claims)  //Adds custom claims to the JWT payload.
                .setIssuedAt(issuedAt)  //Sets the issued at (iat) claim, indicating when the token was created.
                .setExpiration(expiry)  //Sets the expiration (exp) claim, indicating when the token will expire.
                .signWith(SECRET_KEY)   //Signs the JWT using the specified secret key and algorithm.
                .compact(); //Builds the JWT and serializes it into a compact, URL-safe string.
    }
}
