package com.securevault.common;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Statement;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

/**
 * Executes schema.sql using native PostgreSQL JDBC execution.
 * Bypasses Spring's ScriptUtils which cannot parse PL/pgSQL dollar-quoted blocks ($$).
 */
@Component
public class DatabaseSchemaInitializer implements ApplicationRunner {
    private static final Logger log = LoggerFactory.getLogger(DatabaseSchemaInitializer.class);
    private final DataSource dataSource;
    private final boolean shouldInitialize;

    public DatabaseSchemaInitializer(
            ObjectProvider<DataSource> dataSourceProvider,
            @Value("${securevault.schema.auto-init:always}") String initMode) {
        this.dataSource = dataSourceProvider.getIfAvailable();
        this.shouldInitialize = "always".equalsIgnoreCase(initMode);
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!shouldInitialize || dataSource == null) {
            return;
        }
        log.info("Executing native PostgreSQL schema initialization...");
        try (InputStream in = new ClassPathResource("schema.sql").getInputStream();
             Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement()) {
            String sql = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            stmt.execute(sql);
            log.info("PostgreSQL schema initialization completed successfully.");
        } catch (Exception e) {
            log.error("Failed to execute database schema: {}", e.getMessage(), e);
            throw new IllegalStateException("Database schema initialization failed", e);
        }
    }
}
