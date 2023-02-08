package com.metoo.nspm.core.config.websocket.demo;

/**
 * @ServerEndpoint 注解是一个类层次的注解，它的功能主要是将目前的类定义成一个websocket服务器端,
 * 注解的值将被用于监听用户连接的终端访问URL地址,客户端可以通过这个URL来连接到WebSocket服务器端
 */

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.github.pagehelper.Page;
import com.metoo.nspm.core.manager.admin.tools.GroupTools;
import com.metoo.nspm.core.service.nspm.IGroupService;
import com.metoo.nspm.core.service.nspm.INetworkElementService;
import com.metoo.nspm.core.service.zabbix.InterfaceService;
import com.metoo.nspm.dto.NetworkElementDto;
import com.metoo.nspm.entity.nspm.Group;
import com.metoo.nspm.entity.nspm.NetworkElement;
import com.metoo.nspm.entity.zabbix.Interface;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.websocket.*;
import javax.websocket.server.PathParam;
import javax.websocket.server.ServerEndpoint;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @ServerEndpoint 注解是一个类层次的注解，它的功能主要是将目前的类定义成一个websocket服务器端,
 * 注解的值将被用于监听用户连接的终端访问URL地址,客户端可以通过这个URL来连接到WebSocket服务器端
 * 只读属性 readyState 表示连接状态，可以是以下值：
 *
 * 0 - 表示连接尚未建立。
 *
 * 1 - 表示连接已建立，可以进行通信。
 *
 * 2 - 表示连接正在进行关闭。
 *
 * 3 - 表示连接已经关闭或者连接不能打开。
 */
@ServerEndpoint("/notice/test/{userId}")
@Component
@Slf4j
public class NoticeWebsocket {

    //记录连接的客户端
    public static Map<String, Session> clients = new ConcurrentHashMap<>();

    // 记录连接的客户端的参数，定时发送消息
    public static Map<String, Map<String, String>> clientsParams = new ConcurrentHashMap<>();


    // 定时任务 避免同一账号多地登录下，定时任务回显数据无法区分用户
    public static Map<String, Map<String, String>> taskParams = new ConcurrentHashMap<>();//

    /**
     * userId关联sid（解决同一用户id，在多个web端连接的问题）
     */
    public static Map<String, Set<String>> conns = new ConcurrentHashMap<>();

    private String sid = null;

    private String userId;



    private static IGroupService groupService;
    private static GroupTools groupTools;
    private static INetworkElementService networkElementService;
    private static InterfaceService interfaceService;

    @Autowired
    public void setGroupService(IGroupService groupService) {
        NoticeWebsocket.groupService = groupService;
    }

    @Autowired
    public void setGroupTools(GroupTools groupTools) {
        NoticeWebsocket.groupTools = groupTools;
    }

    @Autowired
    public void setNetworkElementService(INetworkElementService networkElementService) {
        NoticeWebsocket.networkElementService = networkElementService;
    }

    @Autowired
    public void setInterfaceService(InterfaceService interfaceService) {
        NoticeWebsocket.interfaceService = interfaceService;
    }

    /**
     * 连接成功后调用的方法
     * @param session
     * @param userId
     */
    @OnOpen
    public void onOpen(Session session, @PathParam("userId") String userId) {
        this.sid = UUID.randomUUID().toString();
        this.userId = userId;
        clients.put(this.sid, session);

        Map userMap = taskParams.get(this.sid);
        if(userMap == null){// 单独记录sid,避免同一账号多地登录
            userMap = new HashMap();
            userMap.put("userId", this.userId);
            taskParams.put(this.sid, userMap);
        }

        Set<String> clientSet = conns.get(userId);
        if (clientSet==null){
            clientSet = new HashSet<>();
            conns.put(userId, clientSet);
        }

        clientSet.add(this.sid);

        log.info(this.sid + "用户Id:" + userId + "连接开启！");
    }

    /**
     * 连接关闭调用的方法
     */
    @OnClose
    public void onClose() {
        log.info(this.sid + "连接断开！");

        clients.remove(this.sid);

        /**
         * 清除定时任务信息
         *
         */
        taskParams.remove(this.sid);
    }

    /**
     * 判断是否连接的方法
     * @return
     */
    public static boolean isServerClose() {
        if (NoticeWebsocket.clients.values().size() == 0) {
            log.info("已断开");
            return true;
        }else {
            log.info("已连接");
            return false;
        }
    }

    /**
     * 发送给所有用户
     * @param noticeType
     */
    public static void sendMessage(String noticeType){
        NoticeWebsocketResp noticeWebsocketResp = new NoticeWebsocketResp();
        noticeWebsocketResp.setNoticeType(noticeType);
        sendMessage(noticeWebsocketResp);
    }

    /**
     * 发送给所有用户
     * @param noticeWebsocketResp
     */
    public static void sendMessage(NoticeWebsocketResp noticeWebsocketResp){
        String message = JSONObject.toJSONString(noticeWebsocketResp);
        for (Session session1 : NoticeWebsocket.clients.values()) {
            try {
                session1.getBasicRemote().sendText(message);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * 根据用户id发送给某一个用户
     * **/
    public static void sendMessageByUserId(String userId, NoticeWebsocketResp noticeWebsocketResp) {
        if (!StringUtils.isEmpty(userId)) {
            String message = JSONObject.toJSONString(noticeWebsocketResp);
            Set<String> clientSet = conns.get(userId);
            if (clientSet != null) {
                Iterator<String> iterator = clientSet.iterator();
                while (iterator.hasNext()) {
                    String sid = iterator.next();
                    Session session = clients.get(sid);
                    if (session != null) {
                        try {
                            session.getBasicRemote().sendText(message);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }
        }
    }


    /**
     * 收到客户端消息后调用的方法
     * @param message
     * @param session
     */
    @OnMessage
    public void onMessage(String message, Session session) {
        log.info("收到来自窗口 " + this.userId + " 的信息:" + message);

        // 测试聊天
//        NoticeWebsocket.sendMessage("测试推送消息");
        // "收到来自窗口 " + this.userId + " 的信息:" + message
//        NoticeWebsocketResp noticeWebsocketResp = new NoticeWebsocketResp();
//        noticeWebsocketResp.setNoticeType("1");
//        noticeWebsocketResp.setNoticeInfo("收到来自窗口 " + this.userId + " 的信息:" + message);
//        sendMessageByUserId("好友Id", getNeAvailable(message));
        // 接收消息
//        parseParams(message);
        parseParams2(message);
        Map map = (Map) JSON.parse(message);
        taskSendMessageByUserId(this.sid, getNeAvailable(map));
    }

    // 处理数据
    public void parseParams(String message){
        Map map = (Map) JSON.parse(message);
        if(map != null && !map.isEmpty()){
            Map userMap = clientsParams.get(this.userId);
            if(map.get("noticeType") != null){
                if(userMap.get(map.get("noticeType").toString()) != null){
                    userMap.remove(map.get("noticeType").toString());
                    userMap.put(map.get("noticeType"), message);
                }else{
                    userMap.put(map.get("noticeType"), message);
                }
                clientsParams.put(this.userId, userMap);
            }
        }
    }

    public void parseParams2(String message){
        Map map = (Map) JSON.parse(message);
        if(map != null && !map.isEmpty()){
            Map userMap = taskParams.get(this.sid);
            if(map.get("noticeType") != null){
                if(userMap.get(map.get("noticeType").toString()) != null){
                    userMap.remove(map.get("noticeType").toString());
                    userMap.put(map.get("noticeType"), message);
                }else{
                    userMap.put(map.get("noticeType"), message);
                }
                taskParams.put(this.sid, userMap);
            }
        }
    }

    // 网元状态
    public NoticeWebsocketResp getNeAvailable(Map map){
        if(map != null && !map.isEmpty()){
            // 获取类型
            if(map.get("noticeType") != null){
                String noticeType = map.get("noticeType").toString();
                if(noticeType.equals("1")){
                    if(map.get("params") != null) {
                        String params = map.get("params").toString();
                        NetworkElementDto dto = JSONObject.parseObject(params, NetworkElementDto.class);
                        if (dto == null) {
                            dto = new NetworkElementDto();
                        }
//                        User user = ShiroUserHolder.currentUser();
                        dto.setUserId(Long.parseLong(this.userId));
                        if (dto.getGroupId() != null) {
                            Group group = this.groupService.selectObjById(dto.getGroupId());
                            if (group != null) {
                                Set<Long> ids = this.groupTools.genericGroupId(group.getId());
                                dto.setGroupIds(ids);
                            }
                        }
                        Page<NetworkElement> page = this.networkElementService.selectConditionQuery(dto);
                        Map nes = new HashMap();
                        if (page.getResult().size() > 0) {
                            // 获取主机状态
                            for (NetworkElement ne : page.getResult()) {
                                if (ne.getIp() != null) {
                                    Interface obj = this.interfaceService.selectObjByIp(ne.getIp());
                                    if (obj != null) {
                                        ne.setAvailable(obj.getAvailable());
                                        ne.setError(obj.getError());
                                        nes.put(ne.getIp(), obj.getAvailable());
                                    }
                                }
                            }
                            NoticeWebsocketResp rep = new NoticeWebsocketResp();
                            rep.setNoticeType(noticeType);
                            rep.setNoticeInfo(nes);
                            return rep;
                        }
                    }
                }
            }
        }
        return null;
    }

    public NoticeWebsocketResp getNeAvailable(String userId, Map map){
        if(map != null && !map.isEmpty()){
            // 获取类型
            if(map.get("noticeType") != null){
                String noticeType = map.get("noticeType").toString();
                if(noticeType.equals("1")){
                    if(map.get("params") != null) {
                        String params = map.get("params").toString();
                        NetworkElementDto dto = JSONObject.parseObject(params, NetworkElementDto.class);
                        if (dto == null) {
                            dto = new NetworkElementDto();
                        }
//                        User user = ShiroUserHolder.currentUser();
                        dto.setUserId(Long.parseLong(userId));
                        if (dto.getGroupId() != null) {
                            Group group = this.groupService.selectObjById(dto.getGroupId());
                            if (group != null) {
                                Set<Long> ids = this.groupTools.genericGroupId(group.getId());
                                dto.setGroupIds(ids);
                            }
                        }
                        Page<NetworkElement> page = this.networkElementService.selectConditionQuery(dto);
                        Map nes = new HashMap();
                        if (page.getResult().size() > 0) {
                            // 获取主机状态
                            for (NetworkElement ne : page.getResult()) {
                                if (ne.getIp() != null) {
                                    Interface obj = this.interfaceService.selectObjByIp(ne.getIp());
                                    if (obj != null) {
                                        ne.setAvailable(obj.getAvailable());
                                        ne.setError(obj.getError());
                                        nes.put(ne.getIp(), obj.getAvailable());
                                    }
                                }
                            }
                            NoticeWebsocketResp rep = new NoticeWebsocketResp();
                            rep.setNoticeType(noticeType);
                            rep.setNoticeInfo(nes);
                            return rep;
                        }
                    }
                }
            }
        }
        return null;
    }

    /**
     * 发生错误时的回调函数
     * @param error
     */
    @OnError
    public void onError(Throwable error) {
        log.info("错误");
        error.printStackTrace();
    }


    /**
     * 根据用户sid发送消息
     * @param sid
     * @param noticeWebsocketResp
     */
    public static void taskSendMessageByUserId(String sid, NoticeWebsocketResp noticeWebsocketResp) {
        if (!StringUtils.isEmpty(sid)) {
            String message = JSONObject.toJSONString(noticeWebsocketResp);
            Map userMap = taskParams.get(sid);
            if (userMap != null) {
                Session session = clients.get(sid);
                if (session != null) {
                    try {
                        session.getBasicRemote().sendText(message);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }

    // 创建定时任务，发送消息
//    @Async
//    @Scheduled(cron = "*/10 * * * * ?")
    public void ExecutionTimer(){
        System.out.println("执行定时任务");
        outCycle:for (String key : taskParams.keySet()){// 校验用户是否已断开，或断开时删除该用户定时任务信息
            Map<String, String> params = taskParams.get(key);
            String userId = null;
            for(String key2 : params.keySet()){
                if(key2.equals("userId")){
                    userId = params.get(key2);
                }
            }
            for(String key2 : params.keySet()){
                if(key2.equals("1")){
                    Map map = JSONObject.parseObject(params.get(key2), Map.class);
                    taskSendMessageByUserId(key, getNeAvailable(userId, map));
                    continue outCycle;
                }
                continue;
            }
        }
    }
}
