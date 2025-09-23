package com.clarium.clarium_sso;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties
public class ClariumSsoApplication {

	public static void main(String[] args) {
		SpringApplication.run(ClariumSsoApplication.class, args);
	}

}
