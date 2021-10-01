import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.apache.http.ParseException;
import org.apache.commons.codec.binary.Base64;

public class APIAuthInterceptor implements HttpRequestInterceptor {

    @Override
    public void process(HttpRequest hr, HttpContext hc) throws HttpException, IOException {
        String apiKey = Settings.getInstance().APIKey;
        String apiKeySecret = Settings.getInstance().APIKeySecret;
        int nonce = (new Random()).nextInt();
        long timeStamp = GetTimestamp();
        String absoluteUri = Settings.getInstance().APIUrl + hr.getRequestLine().getUri().toLowerCase().replace(Settings.getInstance().APISufix, "");
        String urlEncoded = URLEncoder.encode(absoluteUri);
        String contentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        
        String requestMethod = hr.getRequestLine().getMethod();
        if (!requestMethod.equalsIgnoreCase("get")) {
            contentHash = GetShaHash(GetContent(hr));
        }

        String digest = (apiKey + nonce + timeStamp + requestMethod + urlEncoded + contentHash).toLowerCase();
        String signature = GenerateSignature(digest, apiKeySecret);
        
        String auth = (apiKey + ":" + nonce + ":" + timeStamp + ":" + signature).toLowerCase();

        hr.setHeader("Authorization", "FCX " + auth);
    }

    private String GetContent(HttpRequest hr) throws ParseException, IOException {
        HttpEntity entity = ((HttpEntityEnclosingRequest) hr).getEntity();
        String content = "";
        if (entity != null) {
            content = EntityUtils.toString(entity);
        }
        return content;
    }
    
    private long GetTimestamp() {
        return System.currentTimeMillis() / 1000L;
    }

    private String GetShaHash(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return Hex.encodeHexString(md.digest(s.getBytes(StandardCharsets.UTF_8.toString())));
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
            Logger.getLogger(APIAuthInterceptor.class.getName()).log(Level.SEVERE, null, ex);
        }

        return "";
    }

    private String GenerateSignature(String token, String apiKeySecret) {
        byte[] hmacData = null;

        try {
            SecretKeySpec secretKey = new SecretKeySpec(Base64.decodeBase64(apiKeySecret.getBytes(StandardCharsets.UTF_8.toString())), "HmacSHA512");
            Mac mac = Mac.getInstance("HmacSHA512");
            mac.init(secretKey);
            hmacData = mac.doFinal(token.getBytes(StandardCharsets.UTF_8.toString()));

            return Hex.encodeHexString(hmacData);
        } catch (InvalidKeyException | NoSuchAlgorithmException | UnsupportedEncodingException e) {
            Logger.getLogger(APIAuthInterceptor.class.getName()).log(Level.SEVERE, null, e);
        }

        return "";
    }
}
