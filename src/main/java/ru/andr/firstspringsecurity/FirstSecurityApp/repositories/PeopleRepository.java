package ru.andr.firstspringsecurity.FirstSecurityApp.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.andr.firstspringsecurity.FirstSecurityApp.models.Person;

import java.util.Optional;

public interface PeopleRepository extends JpaRepository<Person, Integer> {
    Optional<Person> findByUsername(String username);
}
