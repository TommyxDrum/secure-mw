package it.floro.securemw.processor_svc.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import it.floro.securemw.processor_svc.db.MessageRepository;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
@Service
@AllArgsConstructor
public class PersistenceService {
    private final MessageRepository repo;
    private final ObjectMapper mapper; // creato automaticamente da Spring Boot

    public UUID saveRaw(String topic,
                        int partition,
                        long offset,
                        ObjectNode meta,
                        ObjectNode security,
                        String ciphertextB64,
                        ObjectNode headers) {

        try {
            // JsonNode/ObjectNode -> JSON string (sempre valido)
            String metaJson = (meta != null) ? meta.toString() : "{}";
            String secJson  = (security != null) ? security.toString() : "{}";
            String hdrJson  = (headers != null) ? headers.toString() : null;

            UUID id = repo.insertRaw(
                    topic,
                    partition,
                    offset,
                    metaJson,
                    secJson,
                    ciphertextB64,
                    hdrJson
            );

            return id;
        } catch (Exception e) {
            // LOGGA la causa più specifica
            Throwable root = (e.getCause() != null) ? e.getCause() : e;
            System.err.println("❌ saveRaw failed: " + root.getClass().getSimpleName() + " - " + root.getMessage());
            // rilancia con la causa
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
            String metaJson    = (meta != null) ? meta.toString()    : "{}";
            String payloadJson = (payload != null) ? payload.toString() : "{}";

            repo.insertDecoded(
                    rawId,
                    deviceId,
                    eventTs,
                    metaJson,
                    payloadJson,
                    integrityOk,
                    authOk
            );
        } catch (Exception e) {
            Throwable root = (e.getCause() != null) ? e.getCause() : e;
            System.err.println("❌ saveDecoded failed: " + root.getClass().getSimpleName() + " - " + root.getMessage());
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
