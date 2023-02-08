package com.metoo.nspm.core.manager.integrated.policy;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.TopoPolicyDto;
import com.metoo.nspm.entity.nspm.Order;
import com.metoo.nspm.entity.nspm.Policy;
import com.metoo.nspm.entity.nspm.SysConfig;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Api("策略下发")
@RequestMapping("/nspm/policy")
@RestController
public class TopoIssuedManagerController {

    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private NodeUtil nodeUtil;
    @Autowired
    private IUserService userService;
    @Autowired
    private IPolicyService policyService;
    @Autowired
    private IssuedService issuedService;
    @Autowired
    private IOrderService orderService;


    @ApiOperation("列表")
    @RequestMapping("/push/task/pushtasklist")
    public Object pushtasklist(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/task/pushtasklist";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

//    @ApiOperation("列表")
//    @RequestMapping("/push/task/pushtasklist")
//    public Object pushtasklist(@RequestBody(required = false) TopoPolicyDto dto){
//        SysConfig sysConfig = this.sysConfigService.select();
//
//        String token = sysConfig.getNspmToken();
//        if(token != null){
//            String url = "/push/task/pushtasklist";
//            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
//            if(result != null){
//                List<String> users = this.userService.getObjByLevel(dto.getBranchLevel());
//                if(users == null || users.size() <= 0){
//                    return ResponseUtil.ok();
//                }
//                JSONObject task = JSONObject.parseObject(result.toString());
//                List list = new ArrayList();
//                if(task.get("data") != null){
//                    JSONObject taskData = JSONObject.parseObject(task.get("data").toString());
//                    JSONArray arrays = JSONArray.parseArray(taskData.get("list").toString());
//                    for (Object array : arrays){
//                        JSONObject obj = JSONObject.parseObject(array.toString());
//                        if(obj.get("orderNo") != null){
//                            String theme = obj.get("orderNo").toString();
//                            int index = theme.indexOf("`~");
//                            String userName = "";
//                            if(index != -1){
//                                userName = theme.substring(0,index);
//                                obj.put("userName", theme.substring(0,index));
//                                obj.put("orderNo", theme.substring(index + 2));
//                            }
//                            if(obj.get("orderType").toString().equals("2") || obj.get("orderType").toString().equals("17")){
//                                // 根据工单号查询用户信息
////                                String orderNo =  obj.get("orderNo").toString();
////                                Order order = this.orderService.getObjByOrderNo(orderNo);
//                                // 根据工单id查询用户信息
//                                String taskId =  obj.get("taskId").toString();
//                                Order order = this.orderService.getObjByOrderId(Long.parseLong(taskId));
//
//                                userName = order == null ? "" : order.getUserName();
//                            }
//                            if(users.contains(userName)) {
//                                obj.put("userName", userName);
//                                list.add(obj);
//                            }
//                        }
//
//                    }
//                    taskData.put("list", list);
//                    task.put("data", taskData);
//                }
//                return ResponseUtil.ok(task);
//            }
//            return ResponseUtil.ok();
//        }
//        return ResponseUtil.error();
//    }

    @ApiOperation("策略信息")
    @RequestMapping("/getPolicy")
    public Object policys(@RequestBody Policy policy){
        Map map = new HashMap();
        List<Policy> policys = this.policyService.getObjOrderNo(policy.getOrderNo());
        map.put("policys", policys);
        if(policys.size() > 0){
            Policy obj = policys.get(0);
            map.put("deviceName", obj.getDeviceName());
            map.put("deviceType", obj.getDeviceType());
        }
        return ResponseUtil.ok(map);
    }

    @ApiOperation("下发详情")
    @RequestMapping("/push/recommend/task/getcommand")
    public Object getcommand(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/recommend/task/getcommand";
            Object object = this.nodeUtil.postFormDataBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            JSONArray arrays = JSONArray.parseArray(result.get("data").toString());
            List list = new ArrayList();
            for(Object array : arrays){
                JSONObject obj = JSONObject.parseObject(array.toString());
                Order order = this.orderService.getObjByOrderId(Long.parseLong(obj.get("taskId").toString()));
                if (order != null){
                    obj.put("editUserName", order.getUserName());
                }
                list.add(obj);
            }
            result.put("data", list);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("列表")
    @RequestMapping("/push/task/pushtaskstatuslist")
    public Object pushtaskstatuslist(){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/task/pushtaskstatuslist";
            Object result = this.nodeUtil.postFormDataBody(null, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("获取下发信息")
    @RequestMapping("/push/task/getdevicenum")
    public Object getdevicenum(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/task/getdevicenum";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("下发")
    @RequestMapping("/push/task/startpushtasks")
    public Object startpushtasks(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/task/startpushtasks";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            this.issuedService.pushtaskstatuslist();
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("停止下发")
    @RequestMapping("/push/task/stoppushtasks")
    public Object stoppushtasks(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/task/stoppushtasks";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            this.issuedService.pushtaskstatuslist();
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("下发")
    @RequestMapping("/push/task/checkNatOrder")
    public Object checkNatOrder(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/task/checkNatOrder";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("命令下发")
    @RequestMapping("/push/task/startdevicepushtasks")
    public Object startdevicepushtasks(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/task/startdevicepushtasks";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            // 工单统计
            this.issuedService.pushtaskstatuslist();
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }



    @ApiOperation("命令保存")
    @RequestMapping("/push/recommend/task/editcommand.action")
    public Object editcommand(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/recommend/task/editcommand.action";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("下发计划")
    @RequestMapping("/push/task/setschedule")
    public Object setschedule(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/task/setschedule";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }


}
