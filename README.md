# secure-mw

Middleware PoC: Producer -> (Kafka/Redpanda) -> Processor
con payload cifrato (AES-256-GCM) e firma HMAC-SHA256.

## Moduli
- `producer-svc`: genera payload di telemetria, cifra + firma e pubblica su topic.
- `processor-svc`: consuma dal topic, verifica HMAC e decifra.

## Run locale
1. Avvia broker (es. Redpanda/Kafka).
2. Esporta chiavi (una tantum) e avvia i servizi:
   - `producer-svc`: usa `AES_KEY_B64`, `HMAC_KEY_B64`
   - `processor-svc`: usa le **stesse** variabili

> Non committare mai le chiavi: usa `.env` locale o variabili d'ambiente di sistema.

## Build
- Maven standard: `mvn clean package` nei singoli moduli.

## Note
- Le chiavi vanno ruotate se finiscono in chiaro da qualche parte.
