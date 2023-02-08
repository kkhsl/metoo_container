package com.metoo.nspm.core.service.nspm.impl;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.mapper.nspm.IssuedMapper;
import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.core.utils.httpclient.UrlConvertUtil;
import com.metoo.nspm.dto.TopoPolicyDto;
import com.metoo.nspm.entity.nspm.*;
import org.apache.commons.lang.StringEscapeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.Date;
import java.util.List;

@Service
public class IssuedServiceImpl implements IssuedService {

    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private NodeUtil nodeUtil;
    @Autowired
    private IssuedMapper issuedMapper;
    @Autowired
    private InvisibleService invisibleService;
    @Autowired
    private IPolicyService policyService;
    @Autowired
    private IOrderService orderService;
    @Autowired
    private UrlConvertUtil urlConvertUtil;

    // 执行计算
    @Override
    public void pushtaskstatuslist(){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/task/pushtaskstatuslist";
            Object result = this.nodeUtil.postFormDataBody(null, url, token);
            JSONObject dataJson = JSONObject.parseObject(result.toString());
            if(dataJson.get("data") != null){
                JSONArray arrays = JSONArray.parseArray(dataJson.get("data").toString());
                Integer total0 = 0;
                Integer finished0 = 0;

                Integer total1 = 0;
                Integer finished1 = 0;

                Integer total2 = 0;
                Integer finished2 = 0;

                for (Object array : arrays){
                    JSONObject object = JSONObject.parseObject(array.toString());
                    Task task = new Task();
                    Integer type = null;
                    Integer orderType = Integer.parseInt(object.get("type").toString());
                    if(orderType == 1){
                        finished0 = Integer.parseInt(object.get("finished").toString());
                        total0 = Integer.parseInt(object.get("total").toString());
                    }else if(orderType == 3 || orderType == 5||
                            orderType == 7|| orderType == 6|| orderType == 9){
                        total1 += Integer.parseInt(object.get("total").toString());
                        finished1 += Integer.parseInt(object.get("finished").toString());
                    }else if(orderType == 2 || orderType == 17){
                        total2 += Integer.parseInt(object.get("total").toString());
                        finished2 += Integer.parseInt(object.get("finished").toString());
                    }
                }
                Task task0 = new Task();
                task0.setType(0);
                task0.setTotal(total0);
                task0.setFinished(finished0);
                Task obj = this.issuedMapper.getObjByType(0);
                if(obj == null){
                    this.issuedMapper.save(task0);
                }else{
                    task0.setId(obj.getId());
                    this.issuedMapper.update(task0);
                }

                Task task1 = new Task();
                task1.setType(1);
                task1.setTotal(total1);
                task1.setFinished(finished1);
                Task obj1 = this.issuedMapper.getObjByType(1);
                if(obj1 == null){
                    this.issuedMapper.save(task1);
                }else{
                    task1.setId(obj1.getId());
                    this.issuedMapper.update(task1);
                }

                Task task2 = new Task();
                task2.setType(2);
                task2.setTotal(total2);
                task2.setFinished(finished2);
                Task obj2 = this.issuedMapper.getObjByType(2);
                if(obj2 == null){
                    this.issuedMapper.save(task2);
                }else{
                    task2.setId(obj2.getId());
                    this.issuedMapper.update(task2);
                }

            }
        }
    }

    @Override
    public List<Task> query() {
        return this.issuedMapper.query();
    }

    @Override
    public void queryTask(String invisibleName, String type, List<Policy> policysNew, String command) {
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        // 更新策略orderNo
        String taskUrl = "/push/task/pushtasklist";
        TopoPolicyDto dto = new TopoPolicyDto();
        dto.setPage(1);
        dto.setPsize(20);
        dto.setType(type);
        Object result = this.nodeUtil.postFormDataBody(dto, taskUrl, token);
        JSONObject task = JSONObject.parseObject(result.toString());
        if(task.get("data") != null){
            JSONObject data = JSONObject.parseObject(task.get("data").toString());
            if(data.get("list") != null){
                JSONArray arrays = JSONArray.parseArray(data.get("list").toString());
                for(Object array : arrays){
                    JSONObject order = JSONObject.parseObject(array.toString());
                    String orderNo = order.get("orderNo").toString();
                    String taskId = order.get("taskId").toString();
                    try {
                        String invisibleName1 = this.getInvisible(Integer.parseInt(order.get("taskId").toString()));
                        if(StringEscapeUtils.unescapeJava(invisibleName).equals(invisibleName1)){
                            // 更新字符信息
                            Invisible invisible = new Invisible();
                            invisible.setStatus(0);
                            invisible.setName(invisibleName);
                            this.invisibleService.update(invisible);
                            // 创建工单
                            Order order1 = new Order();
                            order1.setOrderNo(orderNo);
                            User user = ShiroUserHolder.currentUser();
                            order1.setUserId(user.getId());
                            order1.setUserName(user.getUsername());
                            order1.setBranchLevel(user.getGroupLevel());
                            order1.setBranchName(user.getGroupName());
                            order1.setOrderId(taskId);
                            order1.setAddTime(new Date());
                            this.orderService.save(order1);
                            //更新策略
                            String uuid = "";
                            if(policysNew.size() > 0){
                                for(Policy policy : policysNew){
                                    policy.setOrderNo(orderNo);
                                    policy.setInvisible(null);
                                    uuid = policy.getDeviceUuid();
                                }
                                this.policyService.update(policysNew);
                            }
                            // 更新命令行
                            TopoPolicyDto policyDto = new TopoPolicyDto();
                            policyDto.setCommand(command);
                            policyDto.setType("0");
                            policyDto.setTaskId(Integer.parseInt(taskId));
                            policyDto.setDeviceUuid(uuid);
                            String commamdUrl = "/push/recommend/task/editcommand.action";
                            Object obj = this.nodeUtil.postBody(policyDto, commamdUrl, token);
                            break;
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }


    }

    @Override
    public void createOrder(String userName, String type, List<Policy> policysNew) {
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        // 更新策略orderNo
        String taskUrl = "/push/task/pushtasklist";
        TopoPolicyDto dto = new TopoPolicyDto();
        dto.setPage(1);
        dto.setPsize(20);
        dto.setType(type);
        dto.setUserName(userName);
        Object result = this.nodeUtil.postFormDataBody(dto, taskUrl, token);
        JSONObject task = JSONObject.parseObject(result.toString());
        if(task.get("data") != null) {
            JSONObject data = JSONObject.parseObject(task.get("data").toString());
            if (data.get("list") != null) {
                JSONArray arrays = JSONArray.parseArray(data.get("list").toString());
                for (Object array : arrays) {
                    JSONObject order = JSONObject.parseObject(array.toString());
                    String orderNo = order.get("orderNo").toString();
                    String taskId = order.get("taskId").toString();
                    // 创建工单
                    Order order1 = new Order();
                    order1.setOrderNo(orderNo);
                    User user = ShiroUserHolder.currentUser();
                    order1.setUserId(user.getId());
                    order1.setUserName(user.getUsername());
                    order1.setBranchLevel(user.getGroupLevel());
                    order1.setBranchName(user.getGroupName());
                    order1.setOrderId(taskId);
                    order1.setAddTime(new Date());
                    this.orderService.save(order1);
                    //更新策略
                    if (policysNew.size() > 0) {
                        for (Policy policy : policysNew) {
                            policy.setOrderNo(orderNo);
                            policy.setInvisible(null);
                        }
                        this.policyService.update(policysNew);
                    }
                    break;
                }
            }
        }
    }

    public String getInvisible(Integer taskId) throws IOException {
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        String commandUrl = "/push/recommend/task/getcommand";
        TopoPolicyDto policyDto = new TopoPolicyDto();
        policyDto.setTaskId(taskId);
        Object result = this.nodeUtil.postFormDataBody(policyDto, commandUrl, token);
        JSONObject results = JSONObject.parseObject(result.toString());
        JSONArray arrays = JSONArray.parseArray(results.get("data").toString());
        for(Object array : arrays){
            JSONObject data = JSONObject.parseObject(array.toString());
            String command = data.get("command").toString();
            StringReader sr = new StringReader(command);
            BufferedReader br = new BufferedReader(sr);
            String aline = "";
            while ((aline = StringEscapeUtils.unescapeJava(br.readLine())) != null) {
                return aline;
            }
        }
        return null;
    }
}
