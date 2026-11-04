package com.securevault;
import org.junit.jupiter.api.*;import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.jdbc.core.*;import org.springframework.web.context.WebApplicationContext;import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.*;import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import com.securevault.admin.*;import com.securevault.common.SecurityEventRecorder;import java.util.*;import io.jsonwebtoken.*;import io.jsonwebtoken.security.Keys;
import static org.mockito.Mockito.*;import static org.mockito.ArgumentMatchers.*;import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
@SpringBootTest(properties={"security.jwt.secret-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","spring.autoconfigure.exclude=org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration"})
class AdminThreatAuthorizationTest {
 @Autowired WebApplicationContext context;@Autowired FilterChainProxy security;
 @MockitoBean JdbcTemplate jdbc;@MockitoBean AdminService admin;@MockitoBean SecurityEventRecorder events;
 MockMvc mvc;
 @BeforeEach void setup(){mvc=MockMvcBuilders.webAppContextSetup(context).addFilters(security).build();}
 String token(){return Jwts.builder().subject(UUID.randomUUID().toString()).expiration(new Date(System.currentTimeMillis()+60000)).signWith(Keys.hmacShaKeyFor(new byte[48])).compact();}
 @Test void anonymousAndNonAdminCannotReadThreatAnalytics()throws Exception {
  mvc.perform(get("/api/admin/analytics")).andExpect(status().isUnauthorized());
  when(jdbc.queryForObject(contains("SELECT COUNT(*) FROM sessions s JOIN users u ON u.id=s.user_id"),eq(Integer.class),any(Object[].class))).thenReturn(1);
  mvc.perform(get("/api/admin/analytics").header("Authorization","Bearer "+token())).andExpect(status().isForbidden());verifyNoInteractions(admin);
  mvc.perform(get("/api/admin/sharing").header("Authorization","Bearer "+token())).andExpect(status().isForbidden());
 }
 @Test void adminCanReadButForgedTokenCannot()throws Exception {
  when(jdbc.queryForObject(anyString(),eq(Integer.class),any(Object[].class))).thenReturn(1);
  when(jdbc.query(anyString(),any(RowMapper.class),any(Object[].class))).thenReturn(List.of(new AdminPrincipal(UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),"admin","admin@test.invalid")));
  mvc.perform(get("/api/admin/analytics").header("Authorization","Bearer "+token())).andExpect(status().isOk());
  clearInvocations(admin);
  mvc.perform(get("/api/admin/analytics").header("Authorization","Bearer forged-secret-not-valid")).andExpect(status().isUnauthorized());verifyNoInteractions(admin);
 }
}
