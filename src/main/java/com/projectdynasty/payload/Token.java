package com.projectdynasty.payload;

import com.projectdynasty.AuthService;
import com.projectdynasty.models.TokenData;
import de.alexanderwodarz.code.JavaCore;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class Token {

    private final TokenData tokenData;

    public static Token get(String id) {
        TokenData filter = (TokenData) AuthService.DATABASE.getTable(TokenData.class).query().addParameter("id", id).executeOne();
        if (filter == null)
            return null;
        return new Token(filter);
    }

    public static Token create(long userId) {
        TokenData data = AuthService.DATABASE.getTable(TokenData.class);
        data.userId = userId;
        data.id = JavaCore.getRandomString(32);
        data.created = System.currentTimeMillis() / 1000;
        data.last = System.currentTimeMillis() / 1000;
        data.expires = System.currentTimeMillis() / 1000 + AuthService.CONFIG.get("jwt", AuthService.Jwt.class).getExpireRefresh() * 1000L;
        data.insert(true);
        return new Token(data);
    }

    public String getId() {
        return tokenData.id;
    }

    public long getUserId() {
        return tokenData.userId;
    }

    public long getCreated() {
        return tokenData.created;
    }

    public long getLast() {
        return tokenData.last;
    }

    public long getExpires() {
        return tokenData.expires;
    }

}
