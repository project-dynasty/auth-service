package com.projectdynasty.socket;

import com.projectdynasty.AuthService;
import lombok.Getter;
import org.java_websocket.WebSocket;

@Getter
public class WebSocketClient {
    private final WebSocket socket;
    private final String challenge;

    public WebSocketClient(WebSocket socket, String challenge) {
        this.socket = socket;
        this.challenge = challenge;
        AuthService.SOCKET.clients.put(this.challenge, this);
    }

    public void send(String message) {
        this.socket.send(message);
    }
}
