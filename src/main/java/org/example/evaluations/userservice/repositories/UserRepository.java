package org.example.evaluations.userservice.repositories;

import org.example.evaluations.userservice.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    @Override
    Optional<User> findById(Long id);

    Optional<User> findByEmail(String email);

    @Override
    User save(User user); //upsert = update + insert
}
