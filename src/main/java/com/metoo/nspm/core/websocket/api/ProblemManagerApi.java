package com.metoo.nspm.core.websocket.api;

import com.alibaba.fastjson.JSONObject;
import com.github.pagehelper.Page;
import com.metoo.nspm.core.config.websocket.demo.NoticeWebsocketResp;
import com.metoo.nspm.core.service.zabbix.IProblemService;
import com.metoo.nspm.core.utils.query.PageInfo;
import com.metoo.nspm.dto.NspmProblemDTO;
import com.metoo.nspm.entity.zabbix.Problem;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

@RequestMapping("/websocket/api/problem")
@RestController
public class ProblemManagerApi {

    @Autowired
    private IProblemService problemService;

    @ApiOperation("告警信息(分页查询)")
    @GetMapping("/all")
    public NoticeWebsocketResp problempAll(
            @RequestParam(value = "requestParams", required = false) String requestParams){
        Map<String, Object> requestParam = JSONObject.parseObject(requestParams, Map.class);
        NspmProblemDTO dto = new NspmProblemDTO();
        dto.setCurrentPage(Integer.parseInt(requestParam.get("currentPage").toString()));
        dto.setPageSize(Integer.parseInt(requestParam.get("pageSize").toString()));
        Page<Problem> page = this.problemService.selectConditionQuery(dto);
        NoticeWebsocketResp rep = new NoticeWebsocketResp();
        if(page.getResult().size() > 0){
            rep.setNoticeType("8");
            rep.setNoticeStatus(1);
            rep.setNoticeInfo(new PageInfo<Problem>(page));
        }else{
            rep.setNoticeType("8");
            rep.setNoticeStatus(0);
        }
        return rep;
    }

    @ApiOperation("告警信息")
    @GetMapping
    public NoticeWebsocketResp problemp(
            @RequestParam(value = "requestParams", required = false) String requestParams){
        Map<String, Object> requestParam = JSONObject.parseObject(requestParams, Map.class);
        Map params = new HashMap();
        params.put("limit", requestParam.get("limit"));
        List<Problem> problemList = this.problemService.selectObjByMap(params);
        NoticeWebsocketResp rep = new NoticeWebsocketResp();
        if(problemList.size() > 0){
            rep.setNoticeType("6");
            rep.setNoticeStatus(1);
            rep.setNoticeInfo(problemList);
        }else{
            rep.setNoticeType("6");
            rep.setNoticeStatus(0);
        }
        return rep;
    }

    @ApiOperation("拓扑端口事件:可改为只是用：uuid，使用uuid查询数据库获取ip")
    @GetMapping("/interface/event")
    public Object interfaceEvent(@RequestParam(value = "requestParams") String param){
        List problems = new ArrayList();
        if(param != null && !param.equals("")){
            List<Object> requestParams = JSONObject.parseObject(param, List.class);
            List<String> events = new ArrayList<>();
            events.add("tempexceed");
            events.add("cpuexceed");
            events.add("memexceed");
            for (Object requestParam : requestParams){
                String[] str = requestParam.toString().split("&");
                // 获取端口事件状态
                Map params = new HashMap();
                params.clear();
                params.put("ip", str[0]);
                params.put("events", events);
                params.put("event", "is not null");
                params.put("objectid", "is not null");
                List<Problem> problemList = this.problemService.selectObjByMap(params);
                if(problemList.size() > 0){
                    Map event = new HashMap();
                    for(Problem problem : problemList){
                        event.put(problem.getEvent(), problem.getStatus());
                        event.put("uuid", str[1]);
                        problems.add(event);
                    }
                }
            }
        }
        NoticeWebsocketResp rep = new NoticeWebsocketResp();
        if (problems.size() > 0) {
            rep.setNoticeStatus(1);
            rep.setNoticeType("7");
            rep.setNoticeInfo(problems);
        }else{
            rep.setNoticeType("7");
            rep.setNoticeStatus(0);
        }
        return rep;
    }

//    @ApiOperation("告警信息")
//    @GetMapping("/cpu")
//    public NoticeWebsocketResp problemp1(){
//        Map params = new HashMap();
//        List<String> events = new ArrayList<>();
//        events.add("tempexceed");
//        events.add("cpuexceed");
//        events.add("memexceed");
//        params.put("events", events);
//        List<Problem> problemList = this.problemService.selectObjByMap(params);
//        NoticeWebsocketResp rep = new NoticeWebsocketResp();
//        if(problemList.size() > 0){
//            rep.setNoticeType("7");
//            rep.setNoticeStatus(1);
//            rep.setNoticeInfo(problemList);
//        }else{
//            rep.setNoticeType("7");
//            rep.setNoticeStatus(0);
//        }
//        return rep;
//    }

}
