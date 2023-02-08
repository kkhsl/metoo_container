package com.metoo.nspm.core.manager.integrated.socket;

import org.apache.commons.lang.StringUtils;
import org.java_websocket.handshake.ServerHandshake;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URISyntaxException;

@RestController
@RequestMapping("/admin/index")
public class ClientWssManagerController {

    @RequestMapping("/connect")
    public void connect() throws URISyntaxException {
        new ClientWss(new URI("wss://192.168.5.100/discover/webssh")) {
            @Override
            public void onClose(int arg0, String arg1, boolean arg2) {
                // System.out.println(String.format("onClose:【%s】【%s】【%s】", arg0, arg1, arg2));
            }

            @Override
            public void onError(Exception arg0) {
                //System.out.println(String.format("onError:%s", arg0));
            }

            @Override
            public void onMessage(String arg0) {
                try {
                    if (StringUtils.isNotBlank(arg0)) {
                        //业务操作
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                // System.out.println(String.format("onMessage:%s", arg0));
                this.close();
            }

            @Override
            public void onOpen(ServerHandshake arg0) {
                // System.out.println(String.format("onOpen:%s", arg0));

                this.send("请求消息");
            }
        }.connect();
    }
}
