package ru.fcpsr.authapp.repositories;

import org.springframework.data.repository.CrudRepository;
import org.springframework.security.core.userdetails.UserDetails;
import ru.fcpsr.authapp.model.AppUser;

public interface AppUserRepository extends CrudRepository<AppUser, Long> {
    UserDetails findByUsername(String username);
}
