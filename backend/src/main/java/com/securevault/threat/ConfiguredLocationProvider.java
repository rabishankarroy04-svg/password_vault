package com.securevault.threat;
import java.net.*;import java.nio.file.*;import java.time.*;import java.util.*;
import org.springframework.beans.factory.annotation.Value;import org.springframework.stereotype.Component;
/** Optional operator-supplied, verified IP mapping. No network calls or startup secret required. */
@Component
public class ConfiguredLocationProvider implements LocationProvider {
 private final Properties mappings=new Properties();
 public ConfiguredLocationProvider(@Value("${security.threat.geo-file:}") String path){
  if(!path.isBlank())try(var in=Files.newInputStream(Path.of(path))){mappings.load(in);}catch(Exception ex){throw new IllegalArgumentException("Configured geolocation file cannot be read");}
 }
 public static boolean publicIp(String ip){
  if(ip==null||(!ip.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}")&&!(ip.contains(":")&&ip.matches("[0-9a-fA-F:.]+"))))return false;
  try{var a=InetAddress.getByName(ip);if(a.isAnyLocalAddress()||a.isLoopbackAddress()||a.isLinkLocalAddress()||a.isSiteLocalAddress()||a.isMulticastAddress())return false;
   byte[] b=a.getAddress();if(b.length==4){int x=b[0]&255,y=b[1]&255;return x!=0&&x!=127&&x<224&&!(x==100&&y>=64&&y<=127)&&!(x==192&&(y==0||y==2))&&!(x==198&&(y==18||y==19||y==51))&&!(x==203&&y==0);}
   return (b[0]&0xe0)==0x20 && !(b[0]==0x20&&b[1]==0x01&&b[2]==0x0d&&(b[3]&255)==0xb8);
  }catch(Exception e){return false;}
 }
 @Override public Optional<Location> lookup(String ip){
  if(!publicIp(ip))return Optional.empty();
  String raw=mappings.getProperty(ip);if(raw==null)return Optional.empty();String[] p=raw.split("\\|",-1);
  if(p.length!=4||!p[0].matches("[A-Z]{2}")||!p[1].matches("[\\p{L}0-9 ._-]{0,80}")||!p[3].matches("[A-Za-z0-9 ._-]{1,80}"))return Optional.empty();
  try{var date=LocalDate.parse(p[2]);if(date.isAfter(LocalDate.now(ZoneOffset.UTC))||date.isBefore(LocalDate.now(ZoneOffset.UTC).minusDays(30)))return Optional.empty();}catch(Exception e){return Optional.empty();}
  return Optional.of(new Location(p[0],p[1],p[3]));
 }
}
