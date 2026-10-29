package com.securevault;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest(properties = {
    "security.jwt.secret-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "spring.datasource.url=jdbc:postgresql://localhost:5432/securevault_test",
    "spring.autoconfigure.exclude=org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration"
})
@org.junit.jupiter.api.extension.ExtendWith(org.springframework.boot.test.system.OutputCaptureExtension.class)
class ApplicationContextTest {
    @org.springframework.beans.factory.annotation.Autowired org.springframework.context.ApplicationContext context;
    @Test void doesNotCreateOrLogDevelopmentCredentials(org.springframework.boot.test.system.CapturedOutput output){
        org.junit.jupiter.api.Assertions.assertFalse(output.getAll().contains("Using generated security password"));
        org.junit.jupiter.api.Assertions.assertTrue(context.getBeansOfType(org.springframework.security.core.userdetails.UserDetailsService.class).isEmpty());
    }

    @MockitoBean
    JdbcTemplate jdbcTemplate;

    @Test
    void contextLoads() {
    }
}
