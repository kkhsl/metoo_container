package com.metoo.nspm.core.config.websocket.demo;

import com.metoo.nspm.core.utils.ResponseUtil;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;

@RestController
@RequestMapping("/admin/order")
public class OrderController {

    @GetMapping("/test")
    public Object test() {
        NoticeWebsocket.sendMessage("测试推送消息");
//        NoticeWebsocket.sendMessageByUserId("1", "测试单独推送");
        return ResponseUtil.ok();
    }

    @GetMapping("/request")
    public void test(HttpServletRequest request) throws IOException {
        System.out.println(request.getRequestURI());
        System.out.println(request.getRequestURL());
        System.out.println(request.getServletPath());
        System.out.println(request.getContextPath());
        System.out.println(request.getPathInfo());
        System.out.println(request.getMethod());
        System.out.println(request.getRemoteAddr());
        System.out.println(request.getRemotePort());
        System.out.println(request.getRemoteUser());
        System.out.println(request.getRemoteHost());


        System.out.println(request.getContentType());

        ServletInputStream inputStream = request.getInputStream();
        System.out.println(inputStream);

        BufferedReader reader = request.getReader();
        System.out.println(reader);

    }

}
