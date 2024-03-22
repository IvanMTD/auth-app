package ru.fcpsr.authapp.configuration;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import ru.fcpsr.authapp.model.AppUser;
import ru.fcpsr.authapp.model.School;
import ru.fcpsr.authapp.repositories.AppUserRepository;
import ru.fcpsr.authapp.repositories.SchoolRepository;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Iterator;

@Configuration
public class App {
    @Bean
    public CommandLineRunner dataLoader(PasswordEncoder encoder, AppUserRepository appUserRepository, SchoolRepository schoolRepository){
        return args -> {
            setDefaultAdmin(encoder,appUserRepository);
            addSchools(schoolRepository);
        };
    }

    private void setDefaultAdmin(PasswordEncoder encoder, AppUserRepository appUserRepository){
        AppUser appUser = new AppUser();
        appUser.setUsername("admin");
        appUser.setPassword(encoder.encode("admin"));
        appUserRepository.save(appUser);
    }

    private void addSchools(SchoolRepository schoolRepository){
        System.out.println("start process");

        XSSFWorkbook wb = getWorkBookFromXSSF("./src/main/resources/static/file/coords.xlsx");
        XSSFSheet sheet = wb.getSheet("Лист1");
        Iterator<Row> rowIter = sheet.rowIterator();

        while (rowIter.hasNext()){
            Row row = rowIter.next();
            Cell name = row.getCell(2);
            Cell subject = row.getCell(4);
            Cell sport = row.getCell(5);
            Cell address = row.getCell(6);
            Cell phone = row.getCell(7);
            Cell coords = row.getCell(10);

            if(name != null && coords != null) {
                School school = new School();
                school.setTitle(name.toString());
                school.setSubject(subject.toString());
                school.setSport(sport.toString());
                school.setAddress(address.toString());
                school.setPhone(phone.toString());
                String[] parts = coords.toString().split(", ");
                school.setS(Float.parseFloat(parts[0]));
                school.setD(Float.parseFloat(parts[1]));
                schoolRepository.save(school);
            }
        }

        try {
            wb.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        System.out.println("end process");
    }

    private XSSFWorkbook getWorkBookFromXSSF(String filePath){
        try{
            return new XSSFWorkbook(new FileInputStream(filePath));
        }catch (Exception e){
            System.out.println(e.getMessage());
            return null;
        }
    }
}
