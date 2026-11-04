package com.securevault;
import com.securevault.auth.AccountIdentityController;
import com.securevault.common.AccountAuthenticationInterceptor;
import com.securevault.common.AccountPrincipal;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.*;
import org.springframework.mock.web.MockHttpServletRequest;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;
import static org.junit.jupiter.api.Assertions.*;
class AccountIdentityTest {
 @Test void identityRolesAreFetchedForTheAuthenticatedPrincipal(){
  var db=mock(JdbcTemplate.class);var user=UUID.randomUUID();var request=new MockHttpServletRequest();
  // Set the same private request attribute as the interceptor using a mock request boundary.
  request.setAttribute("secureVaultAccount",new AccountPrincipal(user,UUID.randomUUID(),null,"fixture-user","fixture@example.invalid"));
  when(db.query(anyString(),any(RowMapper.class),eq(user))).thenReturn(List.of("ROLE_USER"));
  var result=new AccountIdentityController(db).me(request);
  assertEquals(user,result.id());assertEquals(List.of("ROLE_USER"),result.roles());
  verify(db).query(contains("WHERE ur.user_id=?"),any(RowMapper.class),eq(user));
 }
}
