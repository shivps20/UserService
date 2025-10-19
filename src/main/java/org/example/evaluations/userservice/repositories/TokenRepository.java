package org.example.evaluations.userservice.repositories;

import org.example.evaluations.userservice.model.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TokenRepository extends JpaRepository<Token,Long> {

    @Override
    Token save(Token token);

}
