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
        JSONObject pushNotification = new JSONObject();
        pushNotification.put("custom", twoFa);
        pushNotification.put("message", "Please confirm your login");
        pushNotification.put("title", "Confirm Sign in");
        pushNotification.put("sound", "default");
        pushNotification.put("timeSensitive", true);
        pushNotification.put("customName", "2fa");
        pushNotification.put("live", live);
        send(userId, pushNotification);
    }

    public static void triggerChallengeSolve(long userId) {
        JSONObject pushNotification = new JSONObject();
        pushNotification.put("title", "Neuer Anmeldevorgang");
        pushNotification.put("message", "Es wurde soeben ein neues Gerät in deinem Account via QR Code angemeldet");
        pushNotification.put("sound", "default");
        pushNotification.put("timeSensitive", false);
        send(userId, pushNotification);
    }

    private static void send(long userId, JSONObject send) {
        System.out.println(send);
        ClientThread thread = new ClientThread("https://api.project-dynasty.de/push/send/user/" + userId, ClientThread.RequestMethod.POST);
        thread.setHeaders(AuthService.JWT_UTILS.generatePushAuthorizationToken());
        thread.setBody(send);
        thread.run();
        while (thread.isAlive()) {
        }
    }

}
