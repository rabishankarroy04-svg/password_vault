package com.securevault.threat;
import java.util.Locale;
/** Coarse user-agent labels only; not a physical-device identity or owner. */
public record DeviceMetadata(String category,String os,String browser,String userAgentStatus) {
 public static DeviceMetadata parse(String value){
  String a=value==null?"":value.substring(0,Math.min(value.length(),1024)).toLowerCase(Locale.ROOT);
  if(a.isBlank())return new DeviceMetadata("Unknown","Unknown","Unknown","MISSING");
  if(a.matches(".*(curl/|wget/|python-requests/|postmanruntime/|powershell/|java/|okhttp/|node-fetch|undici|axios/|go-http-client/|bot[/ ;]|crawler|spider).*"))
   return new DeviceMetadata("Unknown","Unknown","Unknown","NON_BROWSER");
  String os=a.contains("android")?"Android":a.contains("iphone")||a.contains("ipad")?"iOS":a.contains("windows")?"Windows":a.contains("macintosh")||a.contains("mac os")?"macOS":a.contains("linux")?"Linux":"Unknown";
  String browser=a.contains("edg/")||a.contains("edga/")||a.contains("edgios/")?"Edge":a.contains("firefox/")||a.contains("fxios/")?"Firefox":a.contains("chrome/")||a.contains("crios/")?"Chrome":a.contains("safari/")?"Safari":"Unknown";
  String category=a.contains("ipad")||a.contains("tablet")||(a.contains("android")&&!a.contains("mobile"))?"Tablet":a.contains("mobile")||a.contains("iphone")?"Mobile":!os.equals("Unknown")?"Desktop/Laptop":"Unknown";
  return new DeviceMetadata(category,os,browser,browser.equals("Unknown")?"UNRECOGNIZED":"BROWSER");
 }
}
