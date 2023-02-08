package com.metoo.nspm.core.websocket.api;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.config.websocket.demo.NoticeWebsocketResp;
import com.metoo.nspm.core.manager.admin.tools.MacUtil;
import com.metoo.nspm.core.service.nspm.IMacService;
import com.metoo.nspm.core.service.nspm.IMacVendorService;
import com.metoo.nspm.entity.nspm.Mac;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RequestMapping("/websocket/api/zabbix")
@RestController
public class TopologyManagerApi {

    @Autowired
    private IMacService macService;
    @Autowired
    private IMacVendorService macVendorService;
    @Autowired
    private MacUtil macUtil;

    @ApiOperation("查询Mac(DT))")
    @GetMapping(value = {"/mac/dt"})
    public NoticeWebsocketResp getObjMac(@RequestParam(value = "requestParams", required = false) String uuid){
        Map params = new HashMap();
        List<String> requestParams = JSONObject.parseObject(uuid, List.class);
        Map map = new HashMap();
        for (String requestParam : requestParams) {
            params.put("uuid", requestParam);
            params.put("tag", "DT");
            List<Mac> macs = this.macService.selectByMap(params);
            this.macUtil.macJoint(macs);
            map.put(requestParam, macs);
        }
        NoticeWebsocketResp rep = new NoticeWebsocketResp();
        if(map.size() > 0){
            rep.setNoticeType("4");
            rep.setNoticeStatus(1);
            rep.setNoticeInfo(map);
        }else{
            rep.setNoticeType("4");
            rep.setNoticeStatus(0);
        }
        return rep;
    }
}
