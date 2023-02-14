package com.projectdynasty.socket;

import com.projectdynasty.payload.Challenge;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;

import java.net.InetSocketAddress;
import java.util.HashMap;

public class SocketServer extends WebSocketServer {

    public HashMap<String, WebSocketClient> clients = new HashMap<>();

    public SocketServer(int port) {
        super(new InetSocketAddress(port));
    }

    public void onOpen(WebSocket webSocket, ClientHandshake clientHandshake) {
        String challenge = clientHandshake.getResourceDescriptor().replaceFirst("/", "");
        if (Challenge.getByChallenge(challenge) == null) {
            webSocket.close();
            return;
        }
        new WebSocketClient(webSocket, challenge);
    }


    public void onClose(WebSocket webSocket, int i, String s, boolean b) {
        clients.entrySet().stream().filter(c -> c.getValue().getSocket() == webSocket).findFirst().ifPresent(p -> clients.remove(p.getKey()));
    }


    public void onMessage(WebSocket webSocket, String s) {
        webSocket.close();
    }


    public void onError(WebSocket webSocket, Exception e) {
        e.printStackTrace();
    }


    public void onStart() {
        setConnectionLostTimeout(100);
    }
}