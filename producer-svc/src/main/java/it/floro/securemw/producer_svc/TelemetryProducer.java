package it.floro.securemw.producer_svc;

import com.fasterxml.jackson.databind.ObjectMapper;
import it.floro.securemw.common.crypto.Crypto;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;




@Component
public class TelemetryProducer {

    private final KafkaTemplate<String, String> kafkaTemplate;
    private final ObjectMapper mapper = new ObjectMapper();
    private final Crypto crypto;

    @Value("${app.topics.telemetry}")
    private String telemetryTopic;

    public TelemetryProducer(
            KafkaTemplate<String, String> kafkaTemplate,
            @Value("${app.security.aesKeyB64}") String aesKeyB64,
            @Value("${app.security.hmacKeyB64}") String hmacKeyB64
    ) {
        this.kafkaTemplate = kafkaTemplate;
        this.crypto = new Crypto(aesKeyB64, hmacKeyB64);
    }

    //Invia un messaggio cifrato ogni secondo
    @Scheduled(fixedDelay = 1000)
    public void sendSecureTelemetry() throws Exception {
        var rnd = ThreadLocalRandom.current();

        // genera temperatura tra 68.0 e 75.0
        double temperature = 68.0 + rnd.nextDouble(7.0);

        // genera vibrazione tra 0.010 e 0.016
        double vibration = 0.010 + rnd.nextDouble(0.006);

        // arrotonda a 1 decimale per temperatura e 3 per vibrazione
        temperature = Math.round(temperature * 10.0) / 10.0;
        vibration = Math.round(vibration * 1000.0) / 1000.0;

        var payload = Map.of(
                "temperature", temperature,
                "vibration", vibration
        );

        // 2️ Serializzazione del payload in JSON
        String plaintext = mapper.writeValueAsString(payload);

        // 3️ Costruzione dei metadati (in chiaro)
        var meta = Map.of(
                "schema", "telemetry.v1",
                "deviceId", "cnc-23",
                "ts", Instant.now().toString(),
                "traceId", UUID.randomUUID().toString(),
                "nonce", UUID.randomUUID().toString() // protegge da replay
        );

        // 4️ Cifratura + firma
        var sec = crypto.encryptAndSign(plaintext);

        // 5️ Costruzione dell’envelope sicuro
        var secureMessage = Map.of(
                "meta", meta,
                "security", Map.of(
                        "alg", "AES-256-GCM+HMAC-SHA256",
                        "iv", sec.get("iv"),
                        "sig", sec.get("sig")
                ),
                "ciphertext", sec.get("ciphertext")
        );

        // 6️ Invio al topic Kafka
        String key = (String) meta.get("deviceId");
        String json = mapper.writeValueAsString(secureMessage);

        kafkaTemplate.send(telemetryTopic, key, json);

        // (Facoltativo) log locale per debug
        System.out.printf("Sent encrypted telemetry | key=%s | json=%s%n", key, json);
    }
}