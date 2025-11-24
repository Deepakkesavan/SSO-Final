package com.clarium.clarium_sso;

import com.clarium.clarium_sso.dto.EnvironmentUrl;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
@EnableConfigurationProperties(EnvironmentUrl.class)
public class ClariumSsoApplication {

	public static void main(String[] args) {
		SpringApplication.run(ClariumSsoApplication.class, args);
	}

}
