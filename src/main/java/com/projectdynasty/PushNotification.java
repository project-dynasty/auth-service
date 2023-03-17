package com.projectdynasty;

import de.alexanderwodarz.code.rest.ClientThread;
import lombok.Builder;
import org.json.JSONObject;

@Builder
public class PushNotification {
    private String message, title, deviceToken, category, sound, customName;
    private boolean timeSensitive;
    private JSONObject custom;

    public static void trigger2fa(long userId, String signInToken, String numbers, boolean live) {
        JSONObject twoFa = new JSONObject();
        twoFa.put("token", signInToken);
        twoFa.put("numbers", numbers);
        JSONObject send = new JSONObject();
        send.put("custom", twoFa);
        send.put("message", "Please confirm your login");
        send.put("title", "Confirm Sign in");
        send.put("sound", "default");
        send.put("timeSensitive", true);
        send.put("customName", "2fa");
        send.put("live", live);
        ClientThread thread = new ClientThread("https://api.project-dynasty.de/push/send/user/" + userId, ClientThread.RequestMethod.POST);
        thread.setHeaders(AuthService.JWT_UTILS.generatePushAuthorizationToken());
        thread.setBody(send);
        thread.run();
        while(thread.isAlive()){
        }
    }

}
