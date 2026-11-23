package com.securevault.common;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Statement;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

/**
 * Executes db/schema.sql using native PostgreSQL JDBC execution.
 * Bypasses Spring's ScriptUtils which cannot parse PL/pgSQL dollar-quoted blocks ($$).
 * Also supports automated database reset when SECUREVAULT_SCHEMA_RESET=true.
 */
@Component
public class DatabaseSchemaInitializer implements InitializingBean {
    private static final Logger log = LoggerFactory.getLogger(DatabaseSchemaInitializer.class);
    private final DataSource dataSource;
    private final boolean shouldInitialize;
    private final boolean resetSchema;

    public DatabaseSchemaInitializer(
            ObjectProvider<DataSource> dataSourceProvider,
            @Value("${securevault.schema.auto-init:always}") String initMode,
            @Value("${securevault.schema.reset:${SECUREVAULT_SCHEMA_RESET:false}}") boolean resetSchema) {
        this.dataSource = dataSourceProvider.getIfAvailable();
        this.shouldInitialize = "always".equalsIgnoreCase(initMode);
        this.resetSchema = resetSchema;
    }

    @Override
    public void afterPropertiesSet() {
        if (!shouldInitialize || dataSource == null) {
            return;
        }

        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement()) {

            if (resetSchema) {
                log.warn("==================================================================");
                log.warn("SECUREVAULT_SCHEMA_RESET IS TRUE: Dropping and recreating public schema...");
                log.warn("==================================================================");
                stmt.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO public;");
                log.info("Public schema dropped and recreated successfully.");
            }

            log.info("Executing native PostgreSQL schema initialization from db/schema.sql...");
            try (InputStream in = new ClassPathResource("db/schema.sql").getInputStream()) {
                String sql = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                stmt.execute(sql);
            }
            log.info("PostgreSQL schema initialization completed successfully.");
        } catch (Exception e) {
            log.error("Failed to execute database schema: {}", e.getMessage(), e);
            throw new IllegalStateException("Database schema initialization failed", e);
        }
    }
}
