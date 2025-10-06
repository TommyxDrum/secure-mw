package it.floro.securemw.processor_svc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import it.floro.securemw.common.crypto.Crypto;
import it.floro.securemw.processor_svc.service.PersistenceService;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
public class TelemetryConsumer {

    private final ObjectMapper mapper;
    private final KafkaTemplate<String, String> kafkaTemplate;
    private final PersistenceService persistence;

    @Value("${app.topics.dlq}")
    private final String dlqTopic;

    private final Crypto crypto;

    // anti-replay (demo in-memory)
    private final Set<String> usedNonces = ConcurrentHashMap.newKeySet();

    public TelemetryConsumer(
            ObjectMapper mapper,
            @Value("${app.security.aesKeyB64}") String aesKeyB64,
            @Value("${app.security.hmacKeyB64}") String hmacKeyB64,
            KafkaTemplate<String, String> kafkaTemplate,
            @Value("${app.topics.dlq}") String dlqTopic,
            PersistenceService persistence
    ) {
        this.mapper = mapper;
        this.crypto = new Crypto(aesKeyB64, hmacKeyB64);
        this.kafkaTemplate = kafkaTemplate;
        this.dlqTopic = dlqTopic;
        this.persistence = persistence;
    }

    @KafkaListener(topics = "${app.topics.telemetry}", groupId = "${spring.kafka.consumer.group-id}")
    public void onMessage(ConsumerRecord<String, String> record) {
        final String value = record.value();
        final String key = record.key();
        final String topic = record.topic();
        final int partition = record.partition();
        final long offset = record.offset();

        UUID rawId = null;

        try {
            // ----- parse envelope -----
            JsonNode root = mapper.readTree(value);
            ObjectNode meta = (ObjectNode) root.path("meta");
            ObjectNode sec = (ObjectNode) root.path("security");
            String ciphertextB64 = root.path("ciphertext").asText();

            String ivB64 = sec.path("iv").asText();
            String sigB64 = sec.path("sig").asText();
            String nonce = meta.path("nonce").asText();

            if (!usedNonces.add(nonce)) {
                throw new IllegalStateException("Replay detected for nonce " + nonce);
            }

            // (facoltativo) headers Kafka -> JSON; qui null per semplicità
            ObjectNode headers = null;

            // 1) Persisto SEMPRE il messaggio grezzo (audit + id per errori)
            rawId = persistence.saveRaw(topic, partition, offset, meta, sec, ciphertextB64, headers);

            // 2) Verify HMAC su (iv || ciphertext)
            byte[] iv = Base64.getDecoder().decode(ivB64);
            byte[] ciphertext = Base64.getDecoder().decode(ciphertextB64);
            byte[] sig = Base64.getDecoder().decode(sigB64);

            byte[] msgForMac = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, msgForMac, 0, iv.length);
            System.arraycopy(ciphertext, 0, msgForMac, iv.length, ciphertext.length);
            crypto.verifyHmac(msgForMac, sig); // throws se invalid

            // 3) Decrypt
            byte[] plain = crypto.decrypt(iv, ciphertext);
            String payloadJson = new String(plain, StandardCharsets.UTF_8);
            ObjectNode payload = (ObjectNode) mapper.readTree(payloadJson);

            // 4) Persisto il decodificato
            String deviceId = meta.path("deviceId").asText();
            String tsStr = meta.path("ts").asText();
            Instant eventTs = Instant.parse(tsStr); // se non valido, lancia e finisce in processing_errors

            persistence.saveDecoded(
                    rawId, deviceId, eventTs,
                    meta, payload,
                    true,  // integrity_ok
                    true   // auth_ok
            );

            log.info("✅ Decrypted & persisted | key={} | payload={}", key, payloadJson);

        } catch (Exception ex) {
            log.warn("Security/processing error | topic={} p={} off={} key={}: {}",
                    topic, partition, offset, key, ex.getMessage());

            if (rawId != null) {
                try {
                    persistence.saveError(
                            rawId,
                            "DECRYPT_OR_VERIFY",
                            "PROCESSING_ERROR",
                            ex.getClass().getSimpleName() + ": " + ex.getMessage(),
                            dlqTopic,
                            1
                    );
                } catch (Exception ignore) {
                    // non bloccare il DLQ
                }
            }

            // invio il messaggio grezzo in DLQ
            kafkaTemplate.send(dlqTopic, key, value);
        }
    }
}