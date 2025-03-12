package backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@SpringBootApplication
public class SceptricApplication {
    public static void main(String[] args) {
        SpringApplication.run(SceptricApplication.class, args);

        try {
            Sceptric.main(args);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Configuration
    public static class WebConfig {
        @Bean
        public WebMvcConfigurer corsConfigurer() {
            return new WebMvcConfigurer() {
                @Override
                public void addCorsMappings(CorsRegistry registry) {
                    registry.addMapping("/**").allowedOrigins("http://localhost:3000");
                }
            };
        }
    }
}