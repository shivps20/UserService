package org.example.evaluations.userservice.repositories;

import org.example.evaluations.userservice.model.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.Date;

@Repository
public interface TokenRepository extends JpaRepository<Token,Long> {

    @Override
    Token save(Token token);

    //Select * from tokens where token_value = ? and expiry_date > current_timestamp
    Optional<Token> findByTokenValueAndExpiryDateAfter(String token, Date currentDate);


}
