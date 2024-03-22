package ru.fcpsr.authapp.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import ru.fcpsr.authapp.repositories.SchoolRepository;
import ru.fcpsr.authapp.services.SchoolService;

import java.security.Principal;

@Controller
@RequiredArgsConstructor
public class MainController {

    private final SchoolService schoolService;

    @GetMapping("/")
    public String getMain(Model model){
        model.addAttribute("schools", schoolService.getAll());
        return "main";
    }

    @GetMapping("/admin")
    public String getAdmin(){
        return "admin";
    }

    @GetMapping("/login")
    public String loginPage(){
        return "login";
    }
}
