package com.securevault.admin;
import java.time.Instant;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
/** Metadata only; protected by the existing /api/admin interceptor. */
@RestController @RequestMapping("/api/admin/sharing")
@CrossOrigin(origins={"http://localhost:3001","http://127.0.0.1:3001"})
public class AdminSharingController {
 private final JdbcTemplate db;
 public AdminSharingController(JdbcTemplate db){this.db=db;}
 public record Row(UUID id,UUID credentialRef,String sender,String recipient,String permission,String status,Instant expiresAt,Instant createdAt){}
 public record Page(List<Row> items,long total,int page,int size){}
 @GetMapping public Page list(@RequestParam(defaultValue="0") int page,@RequestParam(defaultValue="20") int size,@RequestParam(defaultValue="ALL") String status){
  if(page<0||page>10000||size<1||size>100||!Set.of("ALL","ACTIVE","EXPIRED","REVOKED").contains(status))throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid sharing filter or pagination.");
  String source=" FROM (SELECT s.id,s.credential_id,u.username AS sender,r.username AS recipient,s.permission_level,CASE WHEN c.deleted_at IS NOT NULL THEN 'REVOKED' WHEN s.status='ACTIVE' AND s.expires_at<=CURRENT_TIMESTAMP THEN 'EXPIRED' ELSE s.status END AS state,s.expires_at,s.created_at FROM sharing s JOIN users u ON u.id=s.shared_by_user_id JOIN users r ON r.id=s.shared_with_user_id JOIN credentials c ON c.id=s.credential_id) q WHERE (?='ALL' OR state=?)";
  long total=db.queryForObject("SELECT count(*)"+source,Long.class,status,status);
  var items=db.query("SELECT *"+source+" ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?",(r,n)->new Row(r.getObject("id",UUID.class),r.getObject("credential_id",UUID.class),r.getString("sender"),r.getString("recipient"),r.getString("permission_level"),r.getString("state"),r.getTimestamp("expires_at")==null?null:r.getTimestamp("expires_at").toInstant(),r.getTimestamp("created_at").toInstant()),status,status,size,page*size);
  return new Page(items,total,page,size);
 }
}
