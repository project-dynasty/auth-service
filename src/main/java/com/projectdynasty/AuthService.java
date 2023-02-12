package com.projectdynasty;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.projectdynasty.config.JsonConfig;
import com.projectdynasty.security.TwoFactor;
import com.projectdynasty.security.jwt.JwtUtils;
import de.alexanderwodarz.code.FileCore;
import de.alexanderwodarz.code.JavaCore;
import de.alexanderwodarz.code.database.Database;
import de.alexanderwodarz.code.log.Level;
import de.alexanderwodarz.code.log.Log;
import de.alexanderwodarz.code.model.varible.VaribleMap;
import de.alexanderwodarz.code.web.WebCore;
import de.alexanderwodarz.code.web.rest.annotation.RestApplication;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.mindrot.jbcrypt.BCrypt;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.DecimalFormat;
import java.util.List;

@RestApplication
public class AuthService {

    public static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    public static final JsonConfig CONFIG = new JsonConfig(new File("config.json"));

    public static Database DATABASE;
    public static JWTVerifier VERIFIER;
    public static JWTVerifier REFRESH_VERIFIER;
    public static JwtUtils JWT_UTILS;
    public static TwoFactor TWO_FACTOR;

    public static void main(String[] args) throws Exception {
        long time = System.currentTimeMillis();
        JavaCore.initLog();
        if (!new File("logs").exists())
            new File("logs").mkdirs();
        File f = new File("logs/" + System.currentTimeMillis() / 1000 + ".txt");
        f.createNewFile();
        Log.print = s -> new FileCore().appendFile(f, s + "\n");

        loadSettings();

        VERIFIER = JWT.require(Algorithm.HMAC256(CONFIG.get("jwt", Jwt.class).getKey())).withIssuer(CONFIG.get("jwt", Jwt.class).getIss()).build();
        REFRESH_VERIFIER = JWT.require(Algorithm.HMAC256(CONFIG.get("jwt", Jwt.class).getRefreshKey())).withIssuer(CONFIG.get("jwt", Jwt.class).getIss()).build();
        JWT_UTILS = new JwtUtils();
        TWO_FACTOR = new TwoFactor();

        VaribleMap map = new VaribleMap();
        map.put().setKey("port").setValue(6472).build();

        DatabaseConfig databaseConfig = CONFIG.get("db", DatabaseConfig.class);
        DATABASE = new Database(databaseConfig.getHost(), databaseConfig.getUsername(), databaseConfig.getPassword(), databaseConfig.getDb(), false);

        WebCore.start(AuthService.class, map);
        Log.log("Started in " + (System.currentTimeMillis() - time) + "ms", Level.INFO);
    }


    private static void loadSettings() {
        if (!new File("config.json").exists()) {
            initSettings();
            System.exit(1);
        }
    }

    private static void initSettings() {
        Jwt jwt = new Jwt("TCP Rest API", JavaCore.getRandomString(128), JavaCore.getRandomString(128), 3600, 604800);

        Ssl ssl = new Ssl();
        ssl.setType("pkcs12");
        ssl.setPort(8080);

        DatabaseConfig database = new DatabaseConfig("secret", "localhost", "tcp_data", "restapi", 3306);

        CONFIG.set("ssl", ssl);
        CONFIG.set("jwt", jwt);
        CONFIG.set("db", database);
        CONFIG.saveConfig();
    }

    @Getter
    @Setter
    @AllArgsConstructor
    public static class DatabaseConfig {
        private String password, host, db, username;
        private int port;
    }

    @Getter
    @Setter
    @AllArgsConstructor
    public static class Jwt {
        private String iss, key, refreshKey;
        private int expire, expireRefresh;
    }

    @Getter
    @Setter
    static class Ssl {
        private String path = "", password = "", alias = "", type = "";
        private boolean enabled = false;
        private int port;
    }

}
