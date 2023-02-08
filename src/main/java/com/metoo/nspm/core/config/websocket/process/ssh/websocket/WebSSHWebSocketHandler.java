package com.metoo.nspm.core.config.websocket.process.ssh.websocket;

import com.metoo.nspm.core.config.websocket.process.ssh.service.WebSSHService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.*;


/**
 * 处理类
 */
@Component
public class WebSSHWebSocketHandler implements WebSocketHandler {

    @Autowired
    @Qualifier("commentWebSshService")
    private WebSSHService webSSHService;

    private Logger logger = LoggerFactory.getLogger(WebSSHWebSocketHandler.class);

    public WebSSHWebSocketHandler() {
    }

    public void afterConnectionEstablished(WebSocketSession webSocketSession) {
        this.logger.info("用户:{},连接WebSSH", webSocketSession.getAttributes().get("user_uuid"));
        this.webSSHService.initConnection(webSocketSession);
    }

    public void handleMessage(WebSocketSession webSocketSession, WebSocketMessage<?> webSocketMessage) {
        if (webSocketMessage instanceof TextMessage) {
            this.logger.info("用户:{},发送命令:{}", webSocketSession.getAttributes().get("user_uuid"), webSocketMessage.toString());
            this.webSSHService.recvHandle((String)((TextMessage)webSocketMessage).getPayload(), webSocketSession);

        } else if (!(webSocketMessage instanceof BinaryMessage) && !(webSocketMessage instanceof PongMessage)) {
            System.out.println("Unexpected WebSocket message type: " + webSocketMessage);
        }

    }

    public void handleTransportError(WebSocketSession webSocketSession, Throwable throwable) {
        this.logger.error("数据传输错误");
    }

    public void afterConnectionClosed(WebSocketSession webSocketSession, CloseStatus closeStatus) {
        this.logger.info("用户:{}断开webssh连接", String.valueOf(webSocketSession.getAttributes().get("user_uuid")));
        this.webSSHService.close(webSocketSession);
    }

    public boolean supportsPartialMessages() {
        return false;
    }
}
