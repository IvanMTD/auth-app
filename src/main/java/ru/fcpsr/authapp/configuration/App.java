package ru.fcpsr.authapp.configuration;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import ru.fcpsr.authapp.model.AppUser;
import ru.fcpsr.authapp.repositories.AppUserRepository;

@Configuration
public class App {
    @Bean
    public CommandLineRunner dataLoader(PasswordEncoder encoder, AppUserRepository appUserRepository){
        return args -> {
            AppUser appUser = new AppUser();
            appUser.setUsername("admin");
            appUser.setPassword(encoder.encode("admin"));
            appUserRepository.save(appUser);
        };
    }
}
