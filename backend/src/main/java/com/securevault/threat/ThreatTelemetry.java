package com.securevault.threat;
import java.util.*;import java.time.*;
import tools.jackson.databind.json.JsonMapper;
import org.springframework.jdbc.core.JdbcTemplate;import org.springframework.stereotype.Component;import org.springframework.beans.factory.annotation.Value;
@Component
public class ThreatTelemetry {
 public static final List<String> DEVICE_CONTEXT_FIELDS=List.of("category","os","browser","userAgentStatus","deviceStatus","deviceId","locationAvailable","country","region","locationSource");
 private final JdbcTemplate jdbc;private final RiskPolicy policy;private final LocationProvider locations;
 private final int deniedThreshold,deniedWindow,deniedCooldown;
 private final JsonMapper json=JsonMapper.builder().build();
 public ThreatTelemetry(JdbcTemplate jdbc,RiskPolicy policy,LocationProvider locations,
  @Value("${security.threat.denied.threshold:5}") int threshold,@Value("${security.threat.denied.window-minutes:5}") int window,@Value("${security.threat.denied.cooldown-minutes:15}") int cooldown){
  if(threshold<2||threshold>100||window<1||window>60||cooldown<window||cooldown>1440)throw new IllegalArgumentException("Invalid denial settings");
  this.jdbc=jdbc;this.policy=policy;this.locations=locations;this.deniedThreshold=threshold;this.deniedWindow=window;this.deniedCooldown=cooldown;
 }
 public String encode(Object v){return json.writeValueAsString(v);}
 public Map<String,Object> metadata(String agent,String deviceId,String state,String ip){
  var d=DeviceMetadata.parse(agent);var m=new LinkedHashMap<String,Object>();
  m.put("category",d.category());m.put("os",d.os());m.put("browser",d.browser());m.put("userAgentStatus",d.userAgentStatus());
  m.put("deviceStatus",deviceId==null?"Not evaluated":state);
  if(deviceId!=null)m.put("deviceId",deviceId);
  var location=locations.lookup(ip);m.put("locationAvailable",location.isPresent());
  location.ifPresent(l->{m.put("country",l.country());m.put("region",l.region());m.put("locationSource",l.source());});
  return m;
 }
 public UUID audit(UUID user,String action,String result,String ip,String details,Map<String,Object> metadata){
  UUID id=UUID.randomUUID();jdbc.update("INSERT INTO audit_logs (id,user_id,action_type,status,ip_address,details,context) VALUES (?,?,?,?,?,?,?::jsonb)",id,user,action,result,ip,details,encode(metadata));return id;
 }
 public void login(UUID user,String ip,String agent,UUID deviceId,boolean newDevice,boolean newIp,boolean unusual){
  // Caller holds a transaction. Serialize incident decisions for the account/source across instances.
  lock(user+":"+ip);
  Long known=jdbc.queryForObject("SELECT COUNT(*) FROM audit_logs WHERE user_id=? AND action_type='LOGIN' AND status='SUCCESS'",Long.class,user);
  var metadata=metadata(agent,deviceId==null?null:deviceId.toString(),newDevice?"New":"Previously Recognized",ip);
  boolean newLocation=false;
  if(Boolean.TRUE.equals(metadata.get("locationAvailable"))){
   Long seen=jdbc.queryForObject("SELECT COUNT(*) FROM audit_logs WHERE user_id=? AND action_type='LOGIN' AND status='SUCCESS' AND context->>'country'=? AND context->>'region'=?",Long.class,user,metadata.get("country"),metadata.get("region"));
   Long located=jdbc.queryForObject("SELECT COUNT(*) FROM audit_logs WHERE user_id=? AND action_type='LOGIN' AND status='SUCCESS' AND context->>'locationAvailable'='true'",Long.class,user);
   newLocation=located!=null&&located>0&&(seen==null||seen==0);
  }
  boolean baseline=known==null||known==0;
  var risk=policy.assess(!baseline&&newDevice,!baseline&&newIp,!baseline&&newLocation,!baseline&&unusual);
  metadata.put("riskLevel",risk.severity());metadata.put("riskScore",risk.score());metadata.put("riskReason",baseline?"First successful observation establishes a baseline, not a threat.":risk.explanation());
  UUID source=audit(user,"LOGIN","SUCCESS",ip,"Successful sign in; credentials and verification codes omitted",metadata);
  // First account observation establishes a baseline, not an attack.
  if(baseline)return;
  for(String factor:risk.factors())audit(user,factor,"SUCCESS",ip,"Observed login risk signal, not a confirmed attack",metadata);
  if(risk.score()<policy.mediumThreshold()||risk.factors().isEmpty())return;
  String type=risk.factors().size()>1?"COMBINED_LOGIN_RISK":risk.factors().get(0);
  var context=new LinkedHashMap<String,Object>(metadata);context.put("riskFactors",risk.factors());context.put("score",risk.score());
  context.put("severityReason",risk.explanation());context.put("threshold",policy.mediumThreshold());context.put("windowMinutes",15);context.put("eventCount",1);
  raise(user,ip,type,risk.severity(),risk.score(),risk.explanation(),context,List.of(source),15);
 }
 public void denied(String ip,String agent){denied(null,ip,agent);}
 public void denied(UUID user,String ip,String agent){
  lock("denied:"+user+":"+ip);audit(user,"ACCESS_DENIED","FAILURE",ip,"Protected request denied; route parameters and credentials omitted",metadata(agent,null,"Unknown",ip));
  var ids=ids(user,ip,"ACCESS_DENIED",deniedWindow);
  if(ids.size()<deniedThreshold)return;
  var context=new LinkedHashMap<String,Object>(metadata(agent,null,"Unknown",ip));context.put("threshold",deniedThreshold);context.put("windowMinutes",deniedWindow);context.put("eventCount",ids.size());context.put("riskFactors",List.of("REPEATED_ACCESS_DENIED"));
  String reason="Rule REPEATED_ACCESS_DENIED: "+ids.size()+" denied requests >= threshold "+deniedThreshold+" within "+deniedWindow+" minutes; HIGH (75) because the repeated-denial threshold was reached. Only validated account sessions are attributed; otherwise source-only.";
  raise(user,ip,"REPEATED_ACCESS_DENIED","HIGH",75,reason,context,ids,deniedCooldown);
 }
 public void failed(UUID user,String ip,int threshold,int window){
  lock(user+":"+ip);
  var ids=ids(user,ip,"LOGIN_FAILURE",window);if(ids.size()<threshold)return;
  boolean critical=ids.size()>=threshold+2;
  var c=new LinkedHashMap<String,Object>();c.put("threshold",threshold);c.put("criticalThreshold",threshold+2);c.put("windowMinutes",window);c.put("eventCount",ids.size());c.put("riskFactors",List.of("MULTIPLE_FAILED_LOGINS"));
  String reason="Rule MULTIPLE_FAILED_LOGINS: "+ids.size()+" failures >= threshold "+threshold+" within "+window+" minutes. "+(critical?"CRITICAL (100): escalation threshold "+(threshold+2)+" reached.":"HIGH: repeated-failure threshold reached; critical threshold is "+(threshold+2)+".");
  // Update the same incident and evidence together on escalation; no new incident for each failure.
  var existing=jdbc.query("SELECT id FROM security_events WHERE event_type='MULTIPLE_FAILED_LOGINS' AND user_id IS NOT DISTINCT FROM ? AND ip_address=? AND timestamp >= CURRENT_TIMESTAMP-(? * INTERVAL '1 minute') ORDER BY timestamp DESC LIMIT 1 FOR UPDATE",(rs,n)->rs.getObject(1,UUID.class),user,ip,window);
  c.putAll(evidenceContext(c,ids));c.put("suggestedAction","Review failed sign-ins with the account owner and investigate source activity.");
  c.put("evidenceAuditIds",ids.stream().map(UUID::toString).toList());
  if(!existing.isEmpty()){jdbc.update("UPDATE security_events SET severity=?,risk_score=?,detection_reason=?,detection_context=?::jsonb,updated_at=CURRENT_TIMESTAMP WHERE id=?",critical?"CRITICAL":"HIGH",critical?100:Math.min(100,ids.size()*20),reason,encode(c),existing.get(0));return;}
  raise(user,ip,"MULTIPLE_FAILED_LOGINS",critical?"CRITICAL":"HIGH",critical?100:Math.min(100,ids.size()*20),reason,c,ids,window);
 }
 public List<UUID> ids(UUID user,String ip,String action,int window){
  return jdbc.query("SELECT id FROM audit_logs WHERE user_id IS NOT DISTINCT FROM ? AND ip_address=? AND action_type=? AND timestamp >= CURRENT_TIMESTAMP-(? * INTERVAL '1 minute') AND timestamp<=CURRENT_TIMESTAMP ORDER BY timestamp,id",(rs,n)->rs.getObject(1,UUID.class),user,ip,action,window);
 }
 private void lock(String key){jdbc.execute((org.springframework.jdbc.core.ConnectionCallback<Void>)c->{try(var s=c.prepareStatement("SELECT pg_advisory_xact_lock(hashtextextended(?,0))")){s.setString(1,key);s.execute();}return null;});}
 private Map<String,Object> evidenceContext(Map<String,Object> context,List<UUID> evidence){
  var out=new LinkedHashMap<String,Object>();
  if(!evidence.isEmpty()){
   String encoded=jdbc.queryForObject("SELECT context::text FROM audit_logs WHERE id=?",String.class,evidence.get(evidence.size()-1));
   if(encoded!=null){var source=json.readValue(encoded,Map.class);for(String key:DEVICE_CONTEXT_FIELDS){if(source.containsKey(key))out.put(key,source.get(key));}}
  }
  out.putAll(context);return out;
 }
 public void raise(UUID user,String ip,String type,String severity,int score,String reason,Map<String,Object> context,List<UUID> evidence,int cooldown){
  lock("alert:"+type+":"+user+":"+ip);
  Long n=jdbc.queryForObject("SELECT COUNT(*) FROM security_events WHERE event_type=? AND user_id IS NOT DISTINCT FROM ? AND ip_address IS NOT DISTINCT FROM ? AND timestamp>=CURRENT_TIMESTAMP-(? * INTERVAL '1 minute')",Long.class,type,user,ip,cooldown);
  var c=new LinkedHashMap<String,Object>(evidenceContext(context,evidence));c.put("evidenceAuditIds",evidence.stream().map(UUID::toString).toList());c.put("suggestedAction","Verify account activity with the owner, review session/device context and investigate permissions. Do not assume compromise from novelty alone.");
  if(n!=null&&n>0){
   if(type.equals("MFA_FAILURE"))jdbc.update("UPDATE security_events SET severity=?,risk_score=?,detection_reason=?,detection_context=?::jsonb,updated_at=CURRENT_TIMESTAMP WHERE id=(SELECT id FROM security_events WHERE event_type=? AND user_id IS NOT DISTINCT FROM ? AND ip_address IS NOT DISTINCT FROM ? AND timestamp>=CURRENT_TIMESTAMP-(? * INTERVAL '1 minute') ORDER BY timestamp DESC LIMIT 1 FOR UPDATE) AND risk_score<=?",severity,score,reason,encode(c),type,user,ip,cooldown,score);
   return;
  }
  jdbc.update("INSERT INTO security_events (user_id,event_type,severity,risk_score,anomaly_detected,ip_address,alert_title,detection_reason,detection_context) VALUES (?,?,?,?,TRUE,?,?,?,?::jsonb)",user,type,severity,score,ip,type.replace('_',' '),reason,encode(c));
 }
}
