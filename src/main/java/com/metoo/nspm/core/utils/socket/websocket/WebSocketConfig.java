package com.metoo.nspm.core.utils.socket.websocket;

import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;


// @EnableWebSocket
public class WebSocketConfig implements WebSocketConfigurer {

    // 注册WebSocket服务
    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry webSocketHandlerRegistry) {
        //webSocketHandlerRegistry.addHandler()
    }
}
