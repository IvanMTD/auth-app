package ru.fcpsr.authapp.repositories;

import org.springframework.data.repository.CrudRepository;
import ru.fcpsr.authapp.model.School;

public interface SchoolRepository extends CrudRepository<School,Long> {
}
