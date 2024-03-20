package ru.fcpsr.authapp.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MainController {
    @GetMapping("/main")
    public String getMain(){
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
