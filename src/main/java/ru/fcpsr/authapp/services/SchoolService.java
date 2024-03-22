package ru.fcpsr.authapp.services;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import ru.fcpsr.authapp.model.School;
import ru.fcpsr.authapp.repositories.SchoolRepository;

import java.util.List;

@Service
@RequiredArgsConstructor
public class SchoolService {
    private final SchoolRepository schoolRepository;

    public Iterable<School> getAll(){
        return schoolRepository.findAll();
    }
}
