package it.floro.securemw.processor_svc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import it.floro.securemw.producer_svc.crypto.Crypto;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class TelemetryConsumer {

    private final ObjectMapper mapper = new ObjectMapper();
    private final Crypto crypto;
    private final KafkaTemplate<String, String> kafkaTemplate;
    private final String dlqTopic;

    // anti-replay (demo in-memory)
    private final Set<String> usedNonces = ConcurrentHashMap.newKeySet();

    public TelemetryConsumer(
            @Value("${app.security.aesKeyB64}") String aesKeyB64,
            @Value("${app.security.hmacKeyB64}") String hmacKeyB64,
            KafkaTemplate<String, String> kafkaTemplate,
            @Value("${app.topics.dlq}") String dlqTopic
    ) {
        this.crypto = new Crypto(aesKeyB64, hmacKeyB64);
        this.kafkaTemplate = kafkaTemplate;
        this.dlqTopic = dlqTopic;
    }

    @KafkaListener(topics = "${app.topics.telemetry}", groupId = "${spring.kafka.consumer.group-id}")
    public void onMessage(String value,
                          @Header(name = "kafka_receivedMessageKey", required = false) String key) {
        try {
            JsonNode root = mapper.readTree(value);
            JsonNode meta = root.path("meta");
            JsonNode sec  = root.path("security");
            String ciphertextB64 = root.path("ciphertext").asText();
            String ivB64 = sec.path("iv").asText();
            String sigB64 = sec.path("sig").asText();
            String nonce = meta.path("nonce").asText();

            // anti-replay: rifiuta nonce già visti
            if (!usedNonces.add(nonce)) {
                throw new IllegalStateException("Replay detected for nonce " + nonce);
            }

            byte[] iv = Base64.getDecoder().decode(ivB64);
            byte[] ciphertext = Base64.getDecoder().decode(ciphertextB64);
            byte[] sig = Base64.getDecoder().decode(sigB64);

            // 1) verifica HMAC su (iv || ciphertext)
            byte[] msgForMac = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, msgForMac, 0, iv.length);
            System.arraycopy(ciphertext, 0, msgForMac, iv.length, ciphertext.length);
            crypto.verifyHmac(msgForMac, sig); // lancia se firma errata

            // 2) decrypt
            byte[] plain = crypto.decrypt(iv, ciphertext);
            String payloadJson = new String(plain, StandardCharsets.UTF_8);

            System.out.printf("✅ Decrypted | key=%s | payload=%s%n", key, payloadJson);

            // qui potresti fare validazioni, scrivere su DB, chiamare altri servizi, ecc.

        } catch (Exception ex) {
            System.out.printf("Security/processing error for key=%s: %s%n", key, ex.getMessage());
            // manda il messaggio grezzo in DLQ per analisi
            kafkaTemplate.send(new ProducerRecord<>(dlqTopic, key, value));
        }
    }
}