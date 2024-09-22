package com.sid.securityjwt;

import com.sid.securityjwt.config.RsaKeyConfigProperties;
import com.sid.securityjwt.entities.User;
import com.sid.securityjwt.repositories.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
@EnableConfigurationProperties(RsaKeyConfigProperties.class)
public class SecurityJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityJwtApplication.class, args);
    }

    //@Bean
    public CommandLineRunner initializeUser(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {

            User user = User.builder().username("othmaneUser2").email("othmane2@gmail.com").password(passwordEncoder.encode("12345678")).build();

            userRepository.save(user);

        };
    }
}
