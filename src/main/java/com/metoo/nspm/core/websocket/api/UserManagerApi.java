package com.metoo.nspm.core.websocket.api;

import com.metoo.nspm.core.config.websocket.demo.NoticeWebsocketResp;
import com.metoo.nspm.core.service.nspm.IUserService;
import com.metoo.nspm.entity.nspm.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;


@RequestMapping("/websocket/api/user")
@RestController
public class UserManagerApi {

    @Autowired
    private IUserService userService;

    @GetMapping
    private Object user(@RequestParam(value = "userId") Long id){
        User user = this.userService.findObjById(id);
        NoticeWebsocketResp rep = new NoticeWebsocketResp();
        if(user != null){
            rep.setNoticeStatus(1);
            rep.setNoticeInfo(user);
            return rep;
        }else{
            rep.setNoticeStatus(0);
        }
        return rep;
    }
}
