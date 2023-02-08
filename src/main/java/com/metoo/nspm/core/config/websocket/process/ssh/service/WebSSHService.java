package com.metoo.nspm.core.config.websocket.process.ssh.service;

import com.jcraft.jsch.Channel;
import org.springframework.web.socket.WebSocketSession;

import java.io.IOException;

public interface WebSSHService {
    void initConnection(WebSocketSession session);

    void recvHandle(String buffer, WebSocketSession session);

    void sendMessage(WebSocketSession session, byte[] buffer) throws IOException;

    void close(WebSocketSession session);

    void transToSSH(Channel channel, String command) throws IOException;
}
