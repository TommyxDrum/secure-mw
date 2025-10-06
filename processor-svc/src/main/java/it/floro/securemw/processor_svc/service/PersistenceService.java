package it.floro.securemw.processor_svc.service;

import com.fasterxml.jackson.databind.node.ObjectNode;
import it.floro.securemw.processor_svc.db.MessageRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class PersistenceService {
    private final MessageRepository repo;

    public UUID saveRaw(String topic,
                        int partition,
                        long offset,
                        ObjectNode meta,
                        ObjectNode security,
                        String ciphertextB64,
                        ObjectNode headers) {
        try {
            String metaJson = meta != null ? meta.toString() : "{}";
            String secJson = security != null ? security.toString() : "{}";
            String hdrJson = headers != null ? headers.toString() : null;

            UUID id = repo.insertRaw(topic, partition, offset, metaJson, secJson, ciphertextB64, hdrJson);
            return id;
        } catch (Exception e) {
            Throwable root = e.getCause() != null ? e.getCause() : e;
            log.error("saveRaw failed: {} - {}", root.getClass().getSimpleName(), root.getMessage());
            throw new RuntimeException("saveRaw failed", e);
        }
    }

    public void saveDecoded(UUID rawId,
                            String deviceId,
                            Instant eventTs,
                            ObjectNode meta,
                            ObjectNode payload,
                            boolean integrityOk,
                            boolean authOk) {
        try {
            if (eventTs == null) {
                throw new IllegalArgumentException("eventTs is null (meta.ts mancante o non parsabile)");
            }
            String metaJson = meta != null ? meta.toString() : "{}";
            String payloadJson = payload != null ? payload.toString() : "{}";

            repo.insertDecoded(rawId, deviceId, eventTs, metaJson, payloadJson, integrityOk, authOk);
        } catch (Exception e) {
            Throwable root = e.getCause() != null ? e.getCause() : e;
            log.error("saveDecoded failed: {} - {}", root.getClass().getSimpleName(), root.getMessage());
            throw new RuntimeException("persist decoded failed", e);
        }
    }

    public void saveError(UUID rawId,
                          String stage,
                          String code,
                          String msg,
                          String dlqTopic,
                          int attempts) {
        repo.insertError(rawId, stage, code, msg, dlqTopic, attempts);
    }
}