package io.jzheaux.springsecurity.resolutions;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication//(exclude = SecurityAutoConfiguration.class)
public class ResolutionsApplication {

	public static void main(String[] args) {
		SpringApplication.run(ResolutionsApplication.class, args);
	}

}
