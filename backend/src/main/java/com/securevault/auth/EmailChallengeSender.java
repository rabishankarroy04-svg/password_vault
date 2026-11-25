package com.securevault.auth;

import jakarta.annotation.PreDestroy;
import jakarta.mail.MessagingException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;
import org.springframework.web.util.HtmlUtils;
import tools.jackson.databind.json.JsonMapper;

@Component
public class EmailChallengeSender {
    private static final Logger LOG = LoggerFactory.getLogger(EmailChallengeSender.class);
    private final ThreadPoolExecutor alertDelivery = new ThreadPoolExecutor(
            1, 1, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(32),
            task -> new Thread(task, "password-alert-mail"));
    private final JavaMailSender mailSender;
    private final String mailHost;
    private final String fromAddress;
    private final String resendApiKey;
    private final String resendFrom;
    private final String brevoApiKey;
    private final String brevoFrom;
    private final boolean logFallbackEnabled;
    private final HttpClient httpClient;
    private final JsonMapper jsonMapper = JsonMapper.builder().build();

    @Autowired
    public EmailChallengeSender(
            ObjectProvider<JavaMailSender> senderProvider,
            @Value("${spring.mail.host:}") String mailHost,
            @Value("${securevault.mail.from:}") String fromAddress,
            @Value("${resend.api.key:${RESEND_API_KEY:}}") String resendApiKey,
            @Value("${securevault.resend.from:${RESEND_FROM:}}") String resendFrom,
            @Value("${brevo.api.key:${BREVO_API_KEY:}}") String brevoApiKey,
            @Value("${securevault.brevo.from:${BREVO_FROM:}}") String brevoFrom,
            @Value("${securevault.mail.log-fallback:true}") boolean logFallbackEnabled) {
        this.mailSender = senderProvider.getIfAvailable();
        this.mailHost = mailHost == null ? "" : mailHost.trim();
        this.fromAddress = fromAddress == null ? "" : fromAddress.trim();
        this.resendApiKey = resendApiKey == null ? "" : resendApiKey.trim();
        this.resendFrom = resendFrom == null ? "" : resendFrom.trim();
        this.brevoApiKey = brevoApiKey == null ? "" : brevoApiKey.trim();
        this.brevoFrom = brevoFrom == null ? "" : brevoFrom.trim();
        this.logFallbackEnabled = logFallbackEnabled;
        this.httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    }

    public EmailChallengeSender(
            ObjectProvider<JavaMailSender> senderProvider,
            String mailHost,
            String fromAddress) {
        this(senderProvider, mailHost, fromAddress, "", "", "", "", true);
    }

    public boolean hasActiveTransport() {
        return (!resendApiKey.isBlank())
                || (!brevoApiKey.isBlank())
                || (mailSender != null && !mailHost.isBlank() && !fromAddress.isBlank());
    }

    public boolean isConfigured() {
        return hasActiveTransport() || logFallbackEnabled;
    }

    public void sendLoginCode(String address, String code) {
        if (!isConfigured()) throw new IllegalStateException("Email delivery is not configured.");
        String subject = "Your SecureVault sign-in code";
        String plain = "Your SecureVault sign-in code is " + code
                + ". It expires in 5 minutes. If you did not request it, secure your account.";
        String html = """
                <!doctype html>
                <html><head><meta charset="UTF-8"></head>
                <body style="margin:0;padding:24px;background:#0d1829;font-family:Arial,sans-serif;color:#f1f5f9;">
                  <div style="max-width:480px;margin:0 auto;background:#132238;padding:32px;border-radius:12px;border:1px solid #1e3a5f;">
                    <h2 style="color:#60a5fa;margin-top:0;">SecureVault Verification Code</h2>
                    <p>Your sign-in verification code is:</p>
                    <div style="background:#0f172a;padding:16px;border-radius:8px;font-size:28px;letter-spacing:6px;font-weight:bold;color:#38bdf8;text-align:center;margin:24px 0;">
                      %s
                    </div>
                    <p style="color:#94a3b8;font-size:14px;">This code expires in 5 minutes. If you did not request this code, please secure your account immediately.</p>
                  </div>
                </body></html>
                """.formatted(code);

        if (hasActiveTransport()) {
            try {
                sendEmail(address, subject, plain, html);
                return;
            } catch (Exception ex) {
                LOG.error("Failed to deliver sign-in email to {}: {}", address, ex.getMessage());
                LOG.warn("===============================================================");
                LOG.warn("SECUREVAULT MFA SIGN-IN CODE FOR {}: [{}]", address, code);
                LOG.warn("===============================================================");
                if (!logFallbackEnabled) {
                    throw ex;
                }
            }
        } else {
            LOG.warn("===============================================================");
            LOG.warn("SECUREVAULT MFA SIGN-IN CODE FOR {}: [{}]", address, code);
            LOG.warn("===============================================================");
        }
    }

    private static final DateTimeFormatter INVITATION_EXPIRY = DateTimeFormatter
            .ofPattern("d MMM uuuu, HH:mm 'UTC'", Locale.ENGLISH).withZone(ZoneOffset.UTC);

    public void sendExternalInvitation(String address, String sender, String link, Instant expiry, String note) {
        if (!isConfigured()) throw new IllegalStateException("Email delivery is not configured.");

        String expires = INVITATION_EXPIRY.format(expiry);
        boolean hasNote = note != null && !note.isBlank();
        String warning = "If you weren't expecting this invitation, ignore it. Keep the link and verification code private.";
        String plain = """
                SecureVault

                %s shared a credential with you. Open the link and verify your email before viewing it.

                Access Shared Credential: %s
                Access expires on %s.
                %s
                %s
                """.formatted(sender, link, expires, hasNote ? "Message from the sender: " + note : "", warning);
        String html = """
                <!doctype html>
                <html lang="en"><head><meta charset="UTF-8"></head>
                <body style="margin:0;background:#eef2f7;color:#13233b;font-family:Arial,sans-serif">
                  <table role="presentation" width="100%%" cellspacing="0" cellpadding="16">
                    <tr><td align="center">
                      <table role="presentation" width="100%%" cellspacing="0" cellpadding="24"
                             style="max-width:560px;background:#ffffff;border:1px solid #dce5f0;border-radius:14px">
                        <tr><td style="background:#101d35;color:#ffffff;font-weight:bold;font-size:20px">SecureVault</td></tr>
                        <tr><td>
                          <h1 style="margin:0 0 14px;font-size:24px">A credential was shared with you</h1>
                          <p><strong>%s</strong> shared a credential with you. Verify your email before viewing it.</p>
                          %s
                          <p style="margin:24px 0">
                            <a href="%s" style="display:inline-block;padding:14px 18px;background:#164bc5;color:#ffffff;border-radius:8px;font-weight:bold;text-decoration:none">Access Shared Credential</a>
                          </p>
                          <p><strong>Access expires:</strong> %s</p>
                          <p style="border-top:1px solid #dce5f0;padding-top:14px;color:#364b66">%s</p>
                        </td></tr>
                      </table>
                    </td></tr>
                  </table>
                </body></html>
                """.formatted(HtmlUtils.htmlEscape(sender),
                hasNote ? "<p><strong>Message from the sender:</strong> " + HtmlUtils.htmlEscape(note) + "</p>" : "",
                HtmlUtils.htmlEscape(link), expires, HtmlUtils.htmlEscape(warning));

        if (hasActiveTransport()) {
            sendEmail(address, "A credential has been securely shared with you", plain, html);
        } else {
            LOG.warn("===============================================================");
            LOG.warn("SECUREVAULT INVITATION FOR {}: {}", address, link);
            LOG.warn("===============================================================");
        }
    }

    public void sendExternalCode(String address, String code) {
        sendExternalMessage(address, "Verify your SecureVault shared access",
                "Your SecureVault shared access code is " + code + ". It expires in 5 minutes. Do not share it.");
    }

    private void sendExternalMessage(String address, String subject, String body) {
        if (!isConfigured()) throw new IllegalStateException("Email delivery is not configured.");
        if (hasActiveTransport()) {
            sendEmail(address, subject, body, null);
        } else {
            LOG.warn("===============================================================");
            LOG.warn("SECUREVAULT EXTERNAL CODE FOR {}: [{}]", address, body);
            LOG.warn("===============================================================");
        }
    }

    public void queuePasswordFailureAlert(String address, long attempts, Instant alertTime) {
        if (!hasActiveTransport()) {
            LOG.warn("Password failure alert recorded; email transport is unavailable.");
            return;
        }
        try {
            alertDelivery.execute(() -> {
                try {
                    String subject = "SecureVault security alert: failed sign-in attempts";
                    String text = """
                            SecureVault detected %d incorrect password attempts for your account within 15 minutes.
                            The alert was triggered at approximately %s (UTC).

                            If this was you, check your saved sign-in details before trying again.
                            If you do not recognize this activity, open SecureVault directly, review your
                            account security, and change your password if you suspect it was exposed.
                            Never share your password or verification codes.
                            """.formatted(attempts, alertTime.truncatedTo(ChronoUnit.MINUTES));
                    sendEmail(address, subject, text, null);
                } catch (RuntimeException exception) {
                    LOG.warn("Password failure alert email could not be delivered: {}", exception.getMessage());
                }
            });
        } catch (RejectedExecutionException exception) {
            LOG.warn("Password failure alert delivery queue is unavailable.");
        }
    }

    private void sendEmail(String to, String subject, String plain, String html) {
        // 1. Prefer Brevo HTTP API (Port 443 - sends to ANY recipient without needing a custom domain)
        if (!brevoApiKey.isBlank()) {
            try {
                sendViaBrevo(to, subject, plain, html);
                return;
            } catch (Exception ex) {
                LOG.error("Brevo API delivery failed for {}: {}", to, ex.getMessage());
                if (resendApiKey.isBlank() && !hasSmtpTransport()) {
                    throw new RuntimeException("Brevo API delivery failed: " + ex.getMessage(), ex);
                }
            }
        }

        // 2. Try Resend HTTP API (Port 443 - works on Render Free tier)
        if (!resendApiKey.isBlank()) {
            try {
                sendViaResend(to, subject, plain, html);
                return;
            } catch (Exception ex) {
                LOG.error("Resend API delivery failed for {}: {}", to, ex.getMessage());
                if (!hasSmtpTransport()) {
                    throw new RuntimeException("Resend API delivery failed: " + ex.getMessage(), ex);
                }
            }
        }

        // 3. Fallback to SMTP
        if (hasSmtpTransport()) {
            sendViaSmtp(to, subject, plain, html);
            return;
        }

        throw new IllegalStateException("No active email transport available.");
    }

    private boolean hasSmtpTransport() {
        return mailSender != null && !mailHost.isBlank() && !fromAddress.isBlank();
    }

    private void sendViaSmtp(String to, String subject, String plain, String html) {
        if (mailSender == null) {
            throw new IllegalStateException("SMTP mailSender is null");
        }
        if (html != null && !html.isBlank()) {
            var message = mailSender.createMimeMessage();
            try {
                var helper = new MimeMessageHelper(message, MimeMessageHelper.MULTIPART_MODE_MIXED_RELATED,
                        StandardCharsets.UTF_8.name());
                helper.setFrom(fromAddress, "SecureVault");
                helper.setTo(to);
                helper.setSubject(subject);
                helper.setText(plain, html);
            } catch (MessagingException | java.io.UnsupportedEncodingException exception) {
                throw new IllegalStateException("The SecureVault invitation could not be prepared.", exception);
            }
            mailSender.send(message);
        } else {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromAddress);
            message.setTo(to);
            message.setSubject(subject);
            message.setText(plain);
            mailSender.send(message);
        }
    }

    private void sendViaResend(String to, String subject, String plain, String html) throws Exception {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("from", resolveResendFrom());
        payload.put("to", List.of(to));
        payload.put("subject", subject);
        if (plain != null && !plain.isBlank()) {
            payload.put("text", plain);
        }
        if (html != null && !html.isBlank()) {
            payload.put("html", html);
        }

        String jsonBody = jsonMapper.writeValueAsString(payload);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.resend.com/emails"))
                .timeout(Duration.ofSeconds(10))
                .header("Authorization", "Bearer " + resendApiKey)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 400) {
            LOG.error("Resend API rejected message (HTTP {}): {}", response.statusCode(), response.body());
            throw new RuntimeException("Resend API failed with status " + response.statusCode() + ": " + response.body());
        }
        LOG.info("Email delivered successfully via Resend API to {}", to);
    }

    private void sendViaBrevo(String to, String subject, String plain, String html) throws Exception {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("sender", Map.of("name", "SecureVault", "email", resolveBrevoFrom()));
        payload.put("to", List.of(Map.of("email", to)));
        payload.put("subject", subject);
        if (plain != null && !plain.isBlank()) {
            payload.put("textContent", plain);
        }
        if (html != null && !html.isBlank()) {
            payload.put("htmlContent", html);
        }

        String jsonBody = jsonMapper.writeValueAsString(payload);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.brevo.com/v3/smtp/email"))
                .timeout(Duration.ofSeconds(10))
                .header("api-key", brevoApiKey)
                .header("Content-Type", "application/json")
                .header("accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 400) {
            LOG.error("Brevo API rejected message (HTTP {}): {}", response.statusCode(), response.body());
            throw new RuntimeException("Brevo API failed with status " + response.statusCode() + ": " + response.body());
        }
        LOG.info("Email delivered successfully via Brevo API to {}", to);
    }

    private String resolveResendFrom() {
        if (!resendFrom.isBlank()) {
            return resendFrom;
        }
        if (!fromAddress.isBlank() && !fromAddress.toLowerCase(Locale.ROOT).endsWith("@gmail.com")) {
            return fromAddress;
        }
        return "SecureVault <onboarding@resend.dev>";
    }

    private String resolveBrevoFrom() {
        if (!brevoFrom.isBlank()) {
            return brevoFrom;
        }
        if (!fromAddress.isBlank()) {
            return fromAddress;
        }
        return "alerts@securevault.local";
    }

    @PreDestroy
    void stopAlertDelivery() {
        alertDelivery.shutdown();
    }
}
