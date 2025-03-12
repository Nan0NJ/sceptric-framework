package backend.controllers;

import backend.Sceptric;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

@RestController
@RequestMapping("/api")
public class SceptricController {

    @GetMapping("/start")
    public String startFramework() {
        try {
            // Capture console output
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PrintStream ps = new PrintStream(baos);
            PrintStream old = System.out;
            System.setOut(ps);

            // Run Sceptric's main logic
            Sceptric.main(new String[]{});

            // Restore console output and return result
            System.out.flush();
            System.setOut(old);
            return baos.toString();

        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}