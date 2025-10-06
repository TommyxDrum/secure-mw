package it.floro.securemw.processor_svc.db;


import lombok.AllArgsConstructor;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import org.postgresql.util.PGobject;
import org.postgresql.util.PGobject;



@Repository
@AllArgsConstructor
public class MessageRepository {
    private final NamedParameterJdbcTemplate jdbc;

    /* ---------- helpers ---------- */

    private PGobject jsonbOrNull(String json) {
        if (json == null) return null;
        try {
            PGobject obj = new PGobject();
            obj.setType("jsonb");
            obj.setValue(json);
            return obj;
        } catch (Exception e) {
            throw new RuntimeException("Invalid JSON for jsonb param", e);
        }
    }

    /* ---------- RAW ---------- */

    public UUID insertRaw(String topic,
                          int partition,
                          long offset,
                          String metaJson,
                          String securityJson,
                          String ciphertextB64,
                          String headersJson) {

        // NB: "partition" e "offset" sono parole chiave in SQL, quindi le cito.
        final String sql = """
            INSERT INTO messages_raw(topic, "partition", "offset", meta, security, ciphertext_b64, headers)
            VALUES (:topic, :partition, :offset, :meta, :security, :ciphertext, :headers)
            RETURNING id
            """;

        var params = new MapSqlParameterSource()
                .addValue("topic", topic)
                .addValue("partition", partition)
                .addValue("offset", offset)
                .addValue("meta", jsonbOrNull(metaJson))
                .addValue("security", jsonbOrNull(securityJson))
                .addValue("ciphertext", ciphertextB64)
                .addValue("headers", jsonbOrNull(headersJson));

        return jdbc.queryForObject(sql, params, UUID.class);
    }

    /* ---------- DECODED ---------- */

    public void insertDecoded(UUID id,
                              String deviceId,
                              Instant eventTs,
                              String metaJson,
                              String payloadJson,
                              boolean integrityOk,
                              boolean authOk) {

        String sql = """
        INSERT INTO messages_decoded
            (id, device_id, event_ts, processed_at, meta, payload, integrity_ok, auth_ok)
        VALUES
            (:id, :deviceId, :eventTs, now(), :meta, :payload, :integrityOk, :authOk)
        ON CONFLICT (id) DO NOTHING
        """;

        MapSqlParameterSource ps = new MapSqlParameterSource()
                .addValue("id", id)
                .addValue("deviceId", deviceId)
                // meglio convertire esplicitamente a Timestamp (timestamptz in tabella)
                .addValue("eventTs", Timestamp.from(eventTs))
                .addValue("meta",    jsonbOrNull(metaJson))
                .addValue("payload", jsonbOrNull(payloadJson))
                .addValue("integrityOk", integrityOk)
                .addValue("authOk", authOk);

        jdbc.update(sql, ps);
    }

    /* ---------- ERRORS ---------- */

    public void insertError(UUID rawId,
                            String stage,
                            String code,
                            String msg,
                            String dlqTopic,
                            int attempts) {

        final String sql = """
            INSERT INTO processing_errors(raw_id, stage, error_code, error_msg, dlq_topic, attempts)
            VALUES (:rawId, :stage, :code, :msg, :dlq, :attempts)
            """;

        var params = new MapSqlParameterSource()
                .addValue("rawId", rawId)
                .addValue("stage", stage)
                .addValue("code", code)
                .addValue("msg", msg)
                .addValue("dlq", dlqTopic)
                .addValue("attempts", attempts);

        jdbc.update(sql, params);
    }
}
