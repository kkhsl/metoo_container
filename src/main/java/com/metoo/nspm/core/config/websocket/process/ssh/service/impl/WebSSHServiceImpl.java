package com.metoo.nspm.core.config.websocket.process.ssh.service.impl;


import com.jcraft.jsch.Channel;
import com.jcraft.jsch.JSch;
import com.metoo.nspm.core.config.websocket.process.ssh.constant.ConstantPool;
import com.metoo.nspm.core.config.websocket.process.ssh.pojo.SSHConnectInfo;
import com.metoo.nspm.core.config.websocket.process.ssh.service.WebSSHService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;

import java.io.IOException;
import java.io.OutputStream;

@Service
public class WebSSHServiceImpl implements WebSSHService {
    private static final Logger log = LoggerFactory.getLogger(WebSSHServiceImpl.class);
    private Logger logger = LoggerFactory.getLogger(WebSSHServiceImpl.class);

    public WebSSHServiceImpl() {
    }

    public void initConnection(WebSocketSession session) {
        JSch jSch = new JSch();
        SSHConnectInfo sshConnectInfo = new SSHConnectInfo();
        sshConnectInfo.setjSch(jSch);
        sshConnectInfo.setWebSocketSession(session);
        String uuid = String.valueOf(session.getAttributes().get("user_uuid"));
        ConstantPool.SSHMAP.put(uuid, sshConnectInfo);
    }

    public void recvHandle(String buffer, WebSocketSession session) {
    }

    public void sendMessage(WebSocketSession session, byte[] buffer) throws IOException {
        session.sendMessage(new TextMessage(buffer));
    }

    public void close(WebSocketSession session) {
        String userId = String.valueOf(session.getAttributes().get("user_uuid"));
        SSHConnectInfo sshConnectInfo = (SSHConnectInfo)ConstantPool.SSHMAP.get(userId);
        if (sshConnectInfo != null && sshConnectInfo.getChannel() != null) {
            sshConnectInfo.getChannel().disconnect();
        }
        ConstantPool.SSHMAP.remove(userId);
    }

    public void transToSSH(Channel channel, String command) throws IOException {
        if (channel != null) {
            OutputStream outputStream = channel.getOutputStream();
            outputStream.write(command.getBytes());
            outputStream.flush();
        }
    }
}
