package it.floro.securemw.processor_svc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.kafka.annotation.EnableKafka;

@SpringBootApplication
@EnableKafka // abilita la gestione dei @KafkaListener
public class ProcessorSvcApplication {

	public static void main(String[] args) {
		SpringApplication.run(ProcessorSvcApplication.class, args);
	}
}
