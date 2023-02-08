package com.metoo.nspm.core.manager.integrated.policy;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.core.service.nspm.IUserService;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.OperationDto;
import com.metoo.nspm.dto.TopoPolicyDto;
import com.metoo.nspm.entity.nspm.SysConfig;
import com.metoo.nspm.entity.nspm.User;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Api("策略生成")
@RequestMapping("/nspm/operation")
@RestController
public class TopoGenerateManageController {

    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private NodeUtil nodeUtil;
    @Autowired
    private IUserService userService;

    @ApiOperation("仿真开通-命令行")
    @PostMapping(value = "/task/command")
    public Object taskCommand(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url1 = "/push/task/addpushtasks";
            Object result = this.nodeUtil.postFormDataBody(dto, url1, token);
            JSONObject jsonObject = JSONObject.parseObject(result.toString());
            String status = jsonObject.get("status").toString();
            if("0".equals(status)){
                // 根据用户名查询工单记录
                OperationDto operation = new OperationDto();
                operation.setPage(1);
                operation.setPsize(1);
                String url2 = "push/task/pushtasklist";
                Object operations = this.nodeUtil.postFormDataBody(operation, url2, token);
                JSONObject body = JSONObject.parseObject(operations.toString());
                JSONObject data = JSONObject.parseObject(body.get("data").toString());
                Integer total = Integer.parseInt(data.get("total").toString());
                String taskId = "";
                if(total > 0){
                    JSONArray devices = JSONArray.parseArray(data.get("list").toString());
                    JSONObject list = JSONObject.parseObject(devices.get(0).toString());
                    taskId = list.get("taskId").toString();
                }
                if(!taskId.equals("")){
                    OperationDto operation1 = new OperationDto();
                    operation1.setTaskId(Integer.parseInt(taskId));
                    String url3 = "push/recommend/task/getcommand";
                    Object recomment = this.nodeUtil.postFormDataBody(operation1, url3, token);
                    if(recomment != null){
                        // 删除对应工单信息
                        OperationDto operation2 = new OperationDto();
                        operation2.setIds(taskId);
                        String url4 =  "push/recommend/task/deletetask";
                        this.nodeUtil.postFormDataBody(operation2, url4, token);
                        return ResponseUtil.ok(recomment);
                    }
                }
            }
            return ResponseUtil.ok("未匹配到设备！未能生成命令行");
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略生成列表")
    @RequestMapping("push/recommend/task/searchsecuritypolicytasklist")
    public Object searchsecuritypolicytasklist(@RequestBody(required = false) OperationDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/recommend/task/searchsecuritypolicytasklist";
            if(dto.getBranchLevel() == null || dto.getBranchLevel().equals("")){
                User currentUser = ShiroUserHolder.currentUser();
                User user = this.userService.findByUserName(currentUser.getUsername());
                dto.setBranchLevel(user.getGroupLevel());
            }
            Object object = this.nodeUtil.postFormDataBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            JSONObject data = JSONObject.parseObject(result.get("data").toString());
            JSONArray arrays = JSONArray.parseArray(data.get("list").toString());
            List list = new ArrayList();
            for(Object array : arrays){
                JSONObject obj = JSONObject.parseObject(array.toString());
                TopoPolicyDto policy = new TopoPolicyDto();
                policy.setTaskId(Integer.parseInt(obj.get("taskId").toString()));
                policy.setPage(1);
                policy.setPsize(1);
                String url2 = "/push/task/pushtasklist";
                Object taskList = this.nodeUtil.postFormDataBody(policy, url2, token);
                if(taskList != null){
                    JSONObject task = JSONObject.parseObject(taskList.toString());
                    if(!task.get("data").equals("")){
                        JSONObject taskData = JSONObject.parseObject(task.get("data").toString());
                        JSONArray taskArray = JSONArray.parseArray(taskData.get("list").toString());
                        obj.put("task", taskArray.get(0));
                    }else{
                        obj.put("task", "");
                    }
                }
                list.add(obj);
            }
            data.put("list", list);
            result.put("data", data);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

//    @ApiOperation("策略生成列表")
//    @RequestMapping("push/recommend/task/searchsecuritypolicytasklist")
//    public Object searchsecuritypolicytasklist(@RequestBody(required = false) OperationDto dto){
//        SysConfig sysConfig = this.sysConfigService.select();
//        String token = sysConfig.getNspmToken();
//        if(token != null){
//            String url = "/push/recommend/task/searchsecuritypolicytasklist";
//            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
//            JSONObject results = JSONObject.parseObject(result.toString());
//            // 检测用户
//            List<String> users = this.userService.getObjByLevel(dto.getBranchLevel());
//            if(users == null || users.size() <= 0){
//                return ResponseUtil.ok();
//            }
//            JSONObject data = JSONObject.parseObject(results.get("data").toString());
//            JSONArray arrays = JSONArray.parseArray(data.get("list").toString());
//            List list = new ArrayList();
//            for(Object array : arrays){
//                JSONObject obj = JSONObject.parseObject(array.toString());
////                String theme = obj.get("policyName").toString();
////                int index = theme.indexOf("`~");
////                String userName = "";
////                if(index >= 0){
////                    userName = theme.substring(0,index);
////                    obj.put("userName", theme.substring(0,index));
////                    obj.put("policyName", theme.substring(index + 2));
////                }
//                if(users.contains(obj.get("userName").toString())){
//                    TopoPolicyDto policy = new TopoPolicyDto();
//                    policy.setTaskId(Integer.parseInt(obj.get("taskId").toString()));
//                    policy.setPage(1);
//                    policy.setPsize(1);
//                    String url2 = "/push/task/pushtasklist";
//                    Object taskList = this.nodeUtil.postFormDataBody(policy, url2, token);
//                    if(taskList != null){
//                        JSONObject task = JSONObject.parseObject(taskList.toString());
//                        if(!task.get("data").equals("")){
//                            JSONObject taskData = JSONObject.parseObject(task.get("data").toString());
//                            JSONArray taskArray = JSONArray.parseArray(taskData.get("list").toString());
//                            obj.put("task", taskArray.get(0));
//                        }else{
//                            obj.put("task", "");
//                        }
//                    }
//                    list.add(obj);
//                }
//            }
//            data.put("list", list);
//            results.put("data", data);
//            return ResponseUtil.ok(results);
//        }
//        return ResponseUtil.error();
//    }

    @ApiOperation("NAT策略列表")
    @RequestMapping("/push/recommend/task/searchnatpolicytasklist")
    public Object searchnatpolicytasklist(@RequestBody(required = false) OperationDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/recommend/task/searchnatpolicytasklist";
            if(dto.getBranchLevel() == null || dto.getBranchLevel().equals("")){
                User currentUser = ShiroUserHolder.currentUser();
                User user = this.userService.findByUserName(currentUser.getUsername());
                dto.setBranchLevel(user.getGroupLevel());
            }
            Object object = this.nodeUtil.postFormDataBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            JSONObject data = JSONObject.parseObject(result.get("data").toString());
            JSONArray arrays = JSONArray.parseArray(data.get("list").toString());
            List list = new ArrayList();
            for(Object array : arrays){
                JSONObject obj = JSONObject.parseObject(array.toString());
                TopoPolicyDto policy = new TopoPolicyDto();
                System.out.println(obj.get("taskId").toString());
                policy.setTaskId(Integer.parseInt(obj.get("taskId").toString()));
                policy.setPage(1);
                policy.setPsize(1);
                String url2 = "/push/task/pushtasklist";
                Object taskList = this.nodeUtil.postFormDataBody(policy, url2, token);
                if(taskList != null){
                    JSONObject task = JSONObject.parseObject(taskList.toString());
                    if(!task.get("data").equals("")){
                        JSONObject taskData = JSONObject.parseObject(task.get("data").toString());
                        JSONArray taskArray = JSONArray.parseArray(taskData.get("list").toString());
                        obj.put("task", taskArray.get(0));
                    }else{
                        obj.put("task", "");
                    }
                }
                list.add(obj);
            }
            data.put("list", list);
            result.put("data", data);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("场景")
    @RequestMapping("/push/api/disposal/scenes/pageList")
    public Object pageList(@RequestBody(required = false) OperationDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/api/disposal/scenes/pageList";
            Object object = this.nodeUtil.postBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("data") != null){
                List list = new ArrayList();
                JSONObject data = JSONObject.parseObject(result.get("data").toString());
                JSONArray arrays = JSONArray.parseArray(data.get("list").toString());
                for(Object obj : arrays){
                    JSONObject scene = JSONObject.parseObject(obj.toString());
                    String name = scene.get("name").toString();
                    int index = name.indexOf("`~");
                    if(index != -1){
                        String str = name.substring(0, index);
                        scene.put("name", name.substring(str.length() + 2));
                        list.add(scene);
                    }else{
                        list.add(scene);
                    }
                }
                data.put("list",list);
                result.put("data", data);
            }

            return ResponseUtil.ok(result);
//            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略生成（保存）")
    @RequestMapping("push/recommend/task/new-policy-push")
    public Object push(@RequestBody(required = false) OperationDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/recommend/task/new-policy-push";
            User currentUser = ShiroUserHolder.currentUser();
            User user = this.userService.findByUserName(currentUser.getUsername());
            dto.setBranchLevel(user.getGroupLevel());
            dto.setUserName(user.getUsername());
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略生成（删除）")
    @RequestMapping("push/recommend/task/deletesecuritypolicytasklist")
    public Object delete(@RequestBody(required = false) OperationDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/recommend/task/deletesecuritypolicytasklist";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略生成（命令行）")
    @RequestMapping("push/recommend/task/getcommand")
    public Object getcommand(@RequestBody(required = false) OperationDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/recommend/task/getcommand";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略生成（下载）")
    @GetMapping("push/recommend/task/download")
    public Object download(@RequestParam(name = "ids") String ids){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/recommend/download";
            Map map = new HashMap();
            map.put("ids", ids);
            return this.nodeUtil.download(map, url, token);

        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略生成（策略生成导出）")
    @RequestMapping("push/recommend/task/exportTask")
    public Object exportTask(OperationDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/recommend/task/exportTask";
            Object result = this.nodeUtil.getBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略生成（策略下载）")
    @RequestMapping("push/recommend/task/exportTaskDown")
    public Object exportTaskDownLoad(String isReload) {
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if (token != null) {
            String url = "/push/recommend/task/exportTask";
            Map map = new HashMap();
            map.put("isReload", isReload);
            return this.nodeUtil.download(map, url, token);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略生成（批量生成-模板下载）")
    @RequestMapping("push/recommend/task/downloadsecuritytemplate")
    public Object downloadsecuritytemplate() {
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if (token != null) {
            String url = "/push/recommend/task/downloadsecuritytemplate";
            return this.nodeUtil.downloadPost(null, url, token);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("源NAT")
    @RequestMapping("/push/recommend/task/addsrcnatpolicy")
    public Object addsrcnatpolicy(@RequestBody(required = false) OperationDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/recommend/task/addsrcnatpolicy";
            User currentUser = ShiroUserHolder.currentUser();
            User user = this.userService.findByUserName(currentUser.getUsername());
            dto.setBranchLevel(user.getGroupLevel());
            dto.setUserName(user.getUsername());
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("目的NAT")
    @RequestMapping("/push/recommend/task/adddstnatpolicy")
    public Object adddstnatpolicy(@RequestBody(required = false) OperationDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/recommend/task/adddstnatpolicy";
            User currentUser = ShiroUserHolder.currentUser();
            User user = this.userService.findByUserName(currentUser.getUsername());
            dto.setBranchLevel(user.getGroupLevel());
            dto.setUserName(user.getUsername());
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("静态NAT")
    @RequestMapping("/push/recommend/task/addstaticnatpolicy")
    public Object addstaticnatpolicy(@RequestBody(required = false) OperationDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/recommend/task/addstaticnatpolicy";
            User currentUser = ShiroUserHolder.currentUser();
            User user = this.userService.findByUserName(currentUser.getUsername());
            dto.setBranchLevel(user.getGroupLevel());
            dto.setUserName(user.getUsername());
            dto.setBranchLevel(user.getGroupLevel());
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("Both NAT")
    @RequestMapping("/push/recommend/task/addbothnatpolicy")
    public Object addbothnatpolicy(@RequestBody(required = false) OperationDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/recommend/task/addbothnatpolicy";
            User currentUser = ShiroUserHolder.currentUser();
            User user = this.userService.findByUserName(currentUser.getUsername());
            dto.setBranchLevel(user.getGroupLevel());
            dto.setUserName(user.getUsername());
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }
}
