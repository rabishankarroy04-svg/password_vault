package com.securevault.auth;

import com.securevault.common.AccountAuthenticationInterceptor;
import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

/** Identity is resolved from a live session and current database roles, never client selections. */
@RestController @RequestMapping("/api/account/me")
@CrossOrigin(origins={"http://localhost:3000","http://127.0.0.1:3000","http://localhost:3001","http://127.0.0.1:3001"})
public class AccountIdentityController {
 private final JdbcTemplate db;
 public AccountIdentityController(JdbcTemplate db){this.db=db;}
 public record Identity(UUID id,String username,String email,List<String> roles){}
 @GetMapping public Identity me(HttpServletRequest request){
  var actor=AccountAuthenticationInterceptor.principal(request);
  var roles=db.query("SELECT r.role_name FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=? ORDER BY r.role_name",(r,n)->r.getString(1),actor.userId());
  return new Identity(actor.userId(),actor.username(),actor.email(),roles);
 }
}
