package org.example.evaluations.userservice.configs;

import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.boot.autoconfigure.kafka.KafkaProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaAdmin;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class KafkaConfig {

    private final KafkaProperties kafkaProperties;

    public KafkaConfig(KafkaProperties kafkaProperties) {
        this.kafkaProperties = kafkaProperties;
    }

    /**
     * KafkaAdmin — enables admin operations like creating topics at startup.
     */
    @Bean
    public KafkaAdmin kafkaAdmin() {
//        return new KafkaAdmin(kafkaProperties.buildAdminProperties());
        Map<String, Object> configs = new HashMap<>();
        configs.put(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, String.join(",", kafkaProperties.getBootstrapServers()));
        return new KafkaAdmin(configs);
    }

//    // KafkaAdmin (enables programmatic topic creation)
//    @Bean
//    public KafkaAdmin kafkaAdmin() {
//        Map<String, Object> configs = new HashMap<>();
//        configs.put(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapAddress);
//        return new KafkaAdmin(configs);
//    }



    /**
     * ProducerFactory — uses producer settings from application.properties.
     */
    @Bean
    public ProducerFactory<String, String> producerFactory() {
        return new DefaultKafkaProducerFactory<>(kafkaProperties.buildProducerProperties());
    }


//    //Producer Configuration - with recommended reliability settings
//    @Bean
//    public ProducerFactory<String, String> producerFactory() {
//        Map<String, Object> configProps = new HashMap<>();
//        configProps.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapAddress);
//        configProps.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
//        configProps.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG,StringSerializer.class);
//
//
//        // Reliability / performance tuning (recommended)
//        configProps.put(ProducerConfig.ACKS_CONFIG, "all"); // strongest durability
//        configProps.put(ProducerConfig.RETRIES_CONFIG, Integer.MAX_VALUE);
//        configProps.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, true);
//        configProps.put(ProducerConfig.MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION, 5); // safe with idempotence on modern brokers
//        configProps.put(ProducerConfig.LINGER_MS_CONFIG, 5);
//        configProps.put(ProducerConfig.BATCH_SIZE_CONFIG, 32 * 1024); // 32KB
//
//        /**
//         * acks=all + enable.idempotence=true gives strong delivery guarantees.
//         * retries=Integer.MAX_VALUE with idempotence is common for reliable producers; you might prefer a finite value for latency-bound systems.
//         * max.in.flight.requests.per.connection=5 is safe for modern Kafka brokers when idempotence is enabled; set to 1 if you must be extra conservative for older brokers.
//         * linger.ms and batch.size improve throughput but increase latency slightly — adjust to your workload.
//         */
//
//        return new DefaultKafkaProducerFactory<>(configProps);
//    }


    /**
     * KafkaTemplate — main entry point for publishing messages.
     * KafkaTemplate<String, String>  = KafkaTemplate<Topic, Message>
     */
    @Bean
    public KafkaTemplate<String, String> kafkaTemplate(ProducerFactory<String, String> producerFactory) {
        return new KafkaTemplate<>(producerFactory);
    }

    /**
     * Example topic creation at startup.
     * This will auto-create the topic if it does not exist.
     */
    @Bean
    public NewTopic userEventsTopic() {
        return TopicBuilder
                .name("user-events")     // topic name
                .partitions(3)           // number of partitions
                .replicas(1)             // replication factor (1 for local Docker)
                .build();
    }
}
