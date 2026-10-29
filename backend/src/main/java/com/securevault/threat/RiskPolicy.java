package com.securevault.threat;
import java.util.*;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
@Component
public class RiskPolicy {
 public record Assessment(int score,String severity,List<String> factors,String explanation){}
 private final int device,ip,location,time,medium,high,critical;
 public RiskPolicy(Environment env){
  device=bounded(env,"device-weight",25,0,100);ip=bounded(env,"ip-weight",20,0,100);location=bounded(env,"location-weight",20,0,100);time=bounded(env,"time-weight",20,0,100);
  medium=bounded(env,"medium-score",25,1,100);high=bounded(env,"high-score",60,medium,100);critical=bounded(env,"critical-score",85,high,100);
 }
 private int bounded(Environment e,String key,int fallback,int min,int max){int v=e.getProperty("security.threat.risk."+key,Integer.class,fallback);if(v<min||v>max)throw new IllegalArgumentException("Invalid risk setting: "+key);return v;}
 public Assessment assess(boolean newDevice,boolean newIp,boolean newLocation,boolean unusualTime){
  var factors=new LinkedHashMap<String,Integer>();
  if(newDevice)factors.put("NEW_DEVICE_LOGIN",device);
  // Location and IP represent the same network novelty dimension: take the larger, never sum both.
  if(newLocation)factors.put("UNFAMILIAR_LOCATION",Math.max(ip,location));else if(newIp)factors.put("NEW_IP_LOGIN",ip);
  if(unusualTime)factors.put("UNUSUAL_LOGIN_TIME",time);
  int score=Math.min(100,factors.values().stream().mapToInt(Integer::intValue).sum());
  String severity=score>=critical?"CRITICAL":score>=high?"HIGH":score>=medium?"MEDIUM":"LOW";
  return new Assessment(score,severity,List.copyOf(factors.keySet()),"Rule LOGIN_RISK: "+factors+"; score "+score+"; severity "+severity+" using configured boundaries medium="+medium+", high="+high+", critical="+critical+". Network novelty counted once. Investigation priority, not a confirmed attack.");
 }
 public int mediumThreshold(){return medium;}
}
