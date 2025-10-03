package it.floro.securemw.producer_svc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling // abilita il job che invia messaggi periodici
public class ProducerSvcApplication {

	public static void main(String[] args) {
		SpringApplication.run(ProducerSvcApplication.class, args);
	}
}
