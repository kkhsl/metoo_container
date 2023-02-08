package com.metoo.nspm.core.utils.socket.websocket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.websocket.*;
import javax.websocket.server.PathParam;
import java.io.IOException;

/**
 * <p>
 *     Title: TestWebSocket.java
 * </p>
 *
 * <p>
 *     Desciption: Websocket 网络即时通信测试类；
 * </p>
 *
 * <author>
 *     HKK
 * </author>
 */

// @ServerEndpoint("/websorcket/test{userId}")
public class TestWebSocket {

    private Logger logger = LoggerFactory.getLogger(TestWebSocket.class);

    private static String userId; //静态变量，用来记录当前在线连接数。应该把它设计成线程安全的

    public static void main(String[] args) {


    }

    //连接时执行
    @OnOpen
    public void onOpen(@PathParam("userId") String userId, Session session) throws IOException {
        this.userId = userId;
        logger.debug("新连接：{}",userId);
    }

    //关闭时执行
    @OnClose
    public void onClose(){
        logger.debug("连接：{} 关闭",this.userId);
    }

    //收到消息时执行
    @OnMessage
    public void onMessage(String message, Session session) throws IOException {
        logger.debug("收到用户{}的消息{}",this.userId,message);
        session.getBasicRemote().sendText("收到 "+this.userId+" 的消息 "); //回复用户
    }

    //连接错误时执行
    @OnError
    public void onError(Session session, Throwable error){
        logger.debug("用户id为：{}的连接发送错误",this.userId);
        error.printStackTrace();
    }
}
