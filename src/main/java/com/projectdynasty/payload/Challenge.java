package com.projectdynasty.payload;

import com.projectdynasty.AuthService;
import com.projectdynasty.models.ChallengeData;
import com.projectdynasty.socket.WebSocketClient;
import de.alexanderwodarz.code.JavaCore;
import lombok.RequiredArgsConstructor;
import org.json.JSONObject;

@RequiredArgsConstructor
public class Challenge {

    private final ChallengeData data;

    public static Challenge getByChallenge(String challenge) {
        ChallengeData filter = (ChallengeData) AuthService.DATABASE.getTable(ChallengeData.class).query().addParameter("challenge", challenge.replaceAll(" ", "")).executeOne();
        if (filter == null)
            return null;
        return new Challenge(filter);
    }

    public static Challenge get(int id) {
        ChallengeData filter = (ChallengeData) AuthService.DATABASE.getTable(ChallengeData.class).query().addParameter("id", id).executeOne();
        if (filter == null)
            return null;
        return new Challenge(filter);
    }

    public static Challenge create() {
        ChallengeData insert = AuthService.DATABASE.getTable(ChallengeData.class);
        insert.challenge = JavaCore.getRandomString("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 6);
        insert.created = System.currentTimeMillis() / 1000;
        insert.status = "new";
        insert.id = insert.insert();
        return get(insert.id);
    }

    public WebSocketClient getConnectedClient() {
        return AuthService.SOCKET.clients.get(getChallenge());
    }

    public boolean isConnected() {
        return AuthService.SOCKET.clients.containsKey(getChallenge());
    }

    public int getId() {
        return data.id;
    }

    public Long getUserId() {
        return data.user_id;
    }

    public void setUserId(long userId) {
        AuthService.DATABASE.update("UPDATE challenge_data SET user_id='"+userId+"' WHERE id='" + getId() + "';", null);
        data.user_id = userId;
    }

    public String getChallenge() {
        return data.challenge;
    }

    public String getStatus() {
        return data.status;
    }

    public void setStatus(String status) {
        ChallengeData update = AuthService.DATABASE.getTable(ChallengeData.class);
        update.status = status;
        data.update(update, data);
        data.status = status;
    }

    public long getCreated() {
        return data.created;
    }

    public JSONObject build() {
        JSONObject obj = new JSONObject();
        obj.put("created", getCreated());
        obj.put("status", getStatus());
        obj.put("challenge", getChallenge());
        obj.put("userId", getUserId());
        obj.put("id", getId());
        return obj;
    }

}
