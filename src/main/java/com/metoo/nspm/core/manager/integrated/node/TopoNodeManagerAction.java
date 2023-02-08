package com.metoo.nspm.core.manager.integrated.node;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.service.nspm.IGroupService;
import com.metoo.nspm.core.service.nspm.INodeService;
import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.core.service.nspm.IUserService;
import com.metoo.nspm.core.service.topo.ITopoNodeService;
import com.metoo.nspm.core.service.api.zabbix.ZabbixHostInterfaceService;
import com.metoo.nspm.core.service.api.zabbix.ZabbixService;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.abt.AbtHttpClient;
import com.metoo.nspm.core.utils.httpclient.UrlConvertUtil;
import com.metoo.nspm.dto.TopoNodeDto;
import com.metoo.nspm.dto.TopoPolicyDto;
import com.metoo.nspm.entity.nspm.Group;
import com.metoo.nspm.entity.nspm.SysConfig;
import com.metoo.nspm.entity.nspm.TopoNode;
import com.metoo.nspm.entity.nspm.User;
import io.swagger.annotations.ApiModelProperty;
import io.swagger.annotations.ApiOperation;
import org.apache.commons.beanutils.BeanMap;
import org.apache.http.entity.ContentType;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.ResourceUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URLDecoder;
import java.util.*;

//@RequiresPermissions("LK:NODE:MANAGER")
@RequestMapping("/nspm/node")
@RestController
public class TopoNodeManagerAction {

    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private RestTemplate restTemplate;
    @Autowired
    private NodeUtil nodeUtil;
    @Autowired
    private IUserService userService;
    @Autowired
    private IGroupService groupService;
    @Autowired
    private INodeService nodeService;
    @Autowired
    private UrlConvertUtil urlConvertUtil;
    @Autowired
    private ITopoNodeService topoNodeService;
    @Autowired
    private ZabbixService zabbixService;
    @Autowired
    private AbtHttpClient abtHttpClient;
    @Autowired
    private ZabbixHostInterfaceService zabbixHostInterfaceService;

    @ApiOperation("设备列表")
    @GetMapping(value = "/topology-layer/whale/GET/node/navigation")
    public Object nodeNavigation(TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
           if(dto.getBranchLevel() == null || dto.getBranchLevel().equals("")){
               User currentUser = ShiroUserHolder.currentUser();
               User user = this.userService.findByUserName(currentUser.getUsername());
               dto.setBranchLevel(user.getGroupLevel());
           }
            String url = "/topology-layer/whale/GET/node/navigation";
            Object result = this.nodeUtil.getBody(dto, url, token);
            Map map = JSONObject.parseObject(result.toString(), Map.class);
            Map resultMap = new HashMap();
            resultMap.put(0, map.get("0"));
            resultMap.put(1, map.get("1"));
            resultMap.put(3, map.get("3"));
            if(map.get("3") != null){
                Map vendor = JSONObject.parseObject(map.get("3").toString(), Map.class);
                for (Object key : vendor.keySet()){
                    if(key.toString().equals("安博通")){
                        vendor.put("觅通", vendor.get(key.toString()));
                        vendor.remove("安博通");
                    }
                }
                resultMap.put("3", vendor);
            }
            return ResponseUtil.ok(resultMap);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("节点列表")
    @RequestMapping("/nodeQuery")
    public Object nodeQuery(@RequestBody TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "topology/node/queryNode.action";
            if(dto.getBranchLevel() == null || dto.getBranchLevel().equals("")){
                User currentUser = ShiroUserHolder.currentUser();
                User user = this.userService.findByUserName(currentUser.getUsername());
                dto.setBranchLevel(user.getGroupLevel());
            }
            Object result = this.nodeUtil.getBody(dto, url, token);
            JSONObject object = JSONObject.parseObject(result.toString());
            if(object != null){
                List list = new ArrayList();
                if(object.get("data") != null){
                    JSONArray arrays = JSONArray.parseArray(object.get("data").toString());
                    for(Object array : arrays){
                        JSONObject data = JSONObject.parseObject(array.toString());
                        if(data.get("errorMess") != null && !data.get("errorMess").toString().equals("")){
                            String errorMess = data.get("errorMess").toString();
                            if(errorMess.indexOf("脚本异常") > -1){
                                errorMess = errorMess.substring(0, errorMess.indexOf("脚本异常"));
                                data.put("errorMess", errorMess);
                            }
                        }
                        if(data.get("branchLevel") != null){
                           Group group = this.groupService.getObjByLevel(data.get("branchLevel").toString());
                           if(group != null){
                               data.put("branchName", group.getBranchName());
                           }
                        }
                        if(data.get("type") != null){
                            String type = data.get("type").toString();
                            if(type.equals("3")){
                                data.put("vendorName", "觅通");
                                data.put("vendorName", "觅通");
                            }
                        }
                        if(data.get("ip") != null){
                            try {
                                JSONObject hostInterface = this.zabbixHostInterfaceService.getHostInterfaceInfo(data.getString("ip"));
                                if(hostInterface != null){
                                    data.put("available", hostInterface.getString("available"));
                                    data.put("error", hostInterface.getString("error"));
                                }
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                        list.add(data);
                    }
                    object.put("data", list);
                    return ResponseUtil.ok(object);
                }
            }
            return ResponseUtil.ok();
        }
        return ResponseUtil.error();
    }

    @ApiOperation("厂商")
    @RequestMapping("/vendor")
    public Object vendor(@RequestBody(required = false) TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            if(dto == null){
                dto = new TopoNodeDto();
            }
            User currentUser = ShiroUserHolder.currentUser();
            User user = this.userService.findByUserName(currentUser.getUsername());
            dto.setBranchLevel(user.getGroupLevel());
            String url = "/topology/node/getNavigation.action";
            Object object = this.nodeUtil.getBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("3") != null){
                Map vendor = JSONObject.parseObject(result.get("3").toString(), Map.class);
                for (Object key : vendor.keySet()){
                    if(key.toString().equals("安博通")){
                        vendor.put("觅通", vendor.get(key.toString()));
                        vendor.remove("安博通");
                    }
                }
                result.put("3", vendor);
            }

            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("编辑")
    @RequestMapping(value="/device/devices")
    public Object deviceDevices(@RequestBody TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/device/devices/";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

//    @ApiOperation("保存")
//    @RequestMapping(value="/simulation/addGateway")
//    public Object addGateway(@RequestBody TopoNodeDto dto){
//        SysConfig sysConfig = this.sysConfigService.select();
//        String token = sysConfig.getNspmToken();
//        if(token != null){
//            String url = "/topology/node/simulation/addGateway.action/";
//            Object object = this.nodeUtil.postFormDataBody(dto, url, token);
//            return ResponseUtil.ok(object);
//        }
//        return ResponseUtil.error();
//    }

    @ApiOperation("保存")
    @RequestMapping(value="/simulation/addGateway")
    public Object addGateway(@RequestBody TopoNodeDto dto){
        String url = "/topology/node/simulation/addGateway.action/";
        JSONObject json = this.abtHttpClient.post(url, dto, "x-www-form-urlencoded");
        if(json.getBoolean("result")){
            return ResponseUtil.ok(json);
        }
        return ResponseUtil.badArgument(json.getString("msg"));
    }

    @ApiOperation("编辑保存（防火墙）")
    @RequestMapping("/updateNode")
    public Object updateNode(TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/updateNode.action";
            Object result = this.nodeUtil.getBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("在线采集")
    @RequestMapping("/addGatherNode")
    public Object addGatherNode(TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){

            String url = "/topology/node/addGatherNode.action";
            Object object = this.nodeUtil.getBody(dto, url, token);
            // 同步节点到本地(检测ip是否已存储在，存在则为更新)
            JSONObject result = JSONObject.parseObject(object.toString());
//            if(result.get("result") != null && Boolean.valueOf(result.get("result").toString())){
//                TopoNode topoNode = new TopoNode();
//                if(dto.getBranchLevel() == null){
//                    User user = ShiroUserHolder.currentUser();
//                    topoNode.setBranchId(user.getGroupId());
//                    topoNode.setBranchName(user.getGroupName());
//                    topoNode.setBranchLevel(user.getGroupLevel());
//                }
//                BeanUtils.copyProperties(dto, topoNode);
//                // 检测Ip是否已存在
//                TopoNode obj = this.nodeService.getObjByHostAddress(topoNode.getHostAddress());
//                if(obj != null){
//                    this.nodeService.update(topoNode);
//                }else{
//                    this.nodeService.save(topoNode);
//                }
//            }
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("节点保存(local)")
    @RequestMapping("/addGatherNode1")
    public Object addGatherNodeLocal(TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){

            String url = "/topology/node/addGatherNode.action";
            Object object = this.nodeUtil.getBody(dto, url, token);
            // 同步节点到本地(检测ip是否已存储在，存在则为更新)
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("result") != null && Boolean.valueOf(result.get("result").toString())){
                TopoNode topoNode = new TopoNode();

                BeanUtils.copyProperties(dto, topoNode);
                // 根据等级查询等级信息
                Group group = this.groupService.getObjByLevel(dto.getBranchLevel());
                topoNode.setBranchId(group.getId());
                topoNode.setBranchName(group.getBranchName());
                topoNode.setBranchLevel(group.getLevel());
                if(group == null){
                    User user = ShiroUserHolder.currentUser();
                    topoNode.setBranchId(user.getGroupId());
                    topoNode.setBranchName(user.getGroupName());
                    topoNode.setBranchLevel(user.getGroupLevel());
                }
                // 检测Ip是否已存在
                TopoNode obj = this.nodeService.getObjByHostAddress(topoNode.getHostAddress());
                if(obj != null){
                    this.nodeService.update(topoNode);
                }else{
                    topoNode.setAddTime(new Date());
                    this.nodeService.save(topoNode);
                }
            }
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }


    @ApiOperation("验证Ip是否存在")
    @RequestMapping("/booleanExistIPs")
    public Object booleanExistIPs(TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/booleanExistIPs.action";
            Object result = this.nodeUtil.getBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("节点删除")
    @RequestMapping("/nodeDelete")
    public Object nodeDelete(@RequestBody TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/nodeDelete.action";
            Object object = this.nodeUtil.getBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());

            return ResponseUtil.ok(object);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("设备接口")
    @RequestMapping(value="/view/configuration")
    public Object viewConfiguration(@RequestBody TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        String uuid = dto.getUuid();
        if(token != null){
            String url = "/topology/businessSubnet/GET/deviceInfo/" + uuid;
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("业务子网自动学习")
   @PutMapping(value="/deviceBusinessSubnet")
    public Object deviceBusinessSubnet(@RequestBody TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/businessSubnet/PUT/deviceBusinessSubnet/";
            Object result = this.nodeUtil.putBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("设备接口编辑")
    @PutMapping(value="/businessSubnet")
    public Object businessSubnet(@RequestBody TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/businessSubnet/PUT/businessSubnet/";
            Object result = this.nodeUtil.putBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("设备配置")
    @PutMapping(value="device/rawConfig")
    public Object rawConfig(@RequestBody TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/device/rawConfig/";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("采集历史")
    @PostMapping(value="/queryNodeHistory")
    public Object queryNodeHistory(@RequestBody TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/queryNodeHistory.action/";
            Object result = this.nodeUtil.getBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("文件对比")
    @GetMapping(value="/showConfig")
    public Object showConfig(TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/showConfig.action    ";
            Object result = this.nodeUtil.getBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("路由表采集历史")
    @PostMapping(value="/queryRouteTableHistory")
    public Object queryRouteTableHistory(@RequestBody TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/queryRouteTableHistory.action/";
            Object result = this.nodeUtil.getBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("采集历史-配置文件")
    @GetMapping(value="/downloadHistory.action")
    public Object downloadHistory(@RequestParam("id") String id){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url =  "/topology/node/downloadHistory.action";
            Map map = new HashMap();
            map.put("id", id);
            return this.nodeUtil.download(map, url, token);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("路由表-配置下载")
    @GetMapping(value="/downloadRouteTableHistory.action")
    public Object downloadRouteTableHistory(@RequestParam("id") String id){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url =  "/topology/node/downloadRouteTableHistory.action";
            Map map = new HashMap();
            map.put("id", id);
            return this.nodeUtil.download(map, url, token);
        }
        return ResponseUtil.error();
    }


    @ApiOperation("参与路径计算")
    @RequestMapping(value="/updateNodeSkipAnalysis")
    public Object updateNodeSkipAnalysis(@RequestBody TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/updateNodeSkipAnalysis/";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("同进同出")
    @RequestMapping(value="/updateNodeToSameInbound")
    public Object updateNodeToSameInbound(@RequestBody TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/updateNodeToSameInbound/";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("二层设备")
    @RequestMapping(value="/updateNodeLayerTwoDevice")
    public Object updateNodeLayerTwoDevice(@RequestBody TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/updateNodeLayerTwoDevice/";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("变更总览")
    @RequestMapping(value="/device/reversion")
    public Object deviceReversion(@RequestBody TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/device/reversion/";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("变更总览")
    @RequestMapping(value="/device/change")
    public Object deviceChange(@RequestBody TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/device/change/";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("对比")
    @GetMapping(value="/showRouteTableConfig")
    public Object showRouteTableConfig(TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/showRouteTableConfig.action/";
            Object result = this.nodeUtil.getBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }


    @ApiOperation("设备类型")
    @GetMapping(value="/engineJson")
    public Object engineJson(){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/engineJson.action";
            Object result = this.nodeUtil.getBody(null, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("采集凭据/下发凭据")
    @RequestMapping(value="/push/credential/getall")
    public Object push(@RequestBody TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/credential/getall/";
            if(dto.getBranchLevel() == null || dto.getBranchLevel().equals("")){
                User currentUser = ShiroUserHolder.currentUser();
                User user = this.userService.findByUserName(currentUser.getUsername());
                dto.setBranchLevel(user.getGroupLevel());
            }
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("采集周期")
    @GetMapping(value="/cycle/getCyclePage")
    public Object cycleGetCyclePage(){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/cycle/getCyclePage/";
            Object result = this.nodeUtil.getBody(null, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("立即采集")
    @PostMapping(value="/doGather")
    public Object doGather(@RequestBody TopoNodeDto dto) {

        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if (token != null) {
            String url = "/topology/node/doGather.action/";
            Object result = this.nodeUtil.getBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("下载模板")
    @GetMapping(value="/download-import-template")
    public Object download() {
        Object result = this.nodeUtil.getBody(null, "https://t14.baidu.com/it/u=2584240781,50873110&fm=224&app=112&f=JPEG?w=500&h=500&s=E9843472534072F055A8106F0200F063", null);
        return ResponseUtil.ok(result);
    }


    @ApiOperation("批量导入")
    @GetMapping(value="/batch-import-excel")
    public Object batchImportNode(@RequestParam(value = "multipartFile", required = false) MultipartFile file, String encrypt) throws IOException {
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/batch-import-excel/";
            url = this.urlConvertUtil.convert(url);
            ByteArrayResource fileAsResource = new ByteArrayResource(file.getBytes()) {
                @Override
                public String getFilename() {
                    return file.getOriginalFilename();
                }
                @Override
                public long contentLength() {
                    return file.getSize();
                }
            };
            MultiValueMap<String, Object> multipartRequest = new LinkedMultiValueMap<>();
            multipartRequest.add("file", fileAsResource);
            multipartRequest.add("fileName",file.getName());
            multipartRequest.add("fileSize",file.getSize());
            multipartRequest.add("encrypt", encrypt);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.MULTIPART_FORM_DATA);
            headers.set("Authorization", "Bearer " + token);// 设置密钥
            HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity(multipartRequest, headers);
            //发起调用
            Object obj =  restTemplate.postForObject(url, requestEntity, Object.class);
            return ResponseUtil.ok(obj);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("手工采集")
    @PostMapping(value = "/upload")
    public Object upload(@RequestParam(value = "file", required = false) MultipartFile file, TopoNodeDto dto) throws IOException {
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/upload.action/";
            url = this.urlConvertUtil.convert(url);
            ByteArrayResource fileAsResource = new ByteArrayResource(file.getBytes()) {
                @Override
                public String getFilename() {
                    return file.getOriginalFilename();
                }
                @Override
                public long contentLength() {
                    return file.getSize();
                }
            };
            MultiValueMap<String, Object> multValueMap = new LinkedMultiValueMap<>();
            multValueMap.add("file", fileAsResource);
            Map<String, Object> map = new BeanMap(dto);
            for(String key : map.keySet()){
                multValueMap.set(key, map.get(key));
            }
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.MULTIPART_FORM_DATA);
            headers.set("Authorization", "Bearer " + token);// 设置密钥
            HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity(multValueMap, headers);
            //发起调用
            Object obj =  restTemplate.postForObject(url, requestEntity, Object.class);
            JSONObject result = JSONObject.parseObject(JSON.toJSONString(obj));
            if(result.getBoolean("result")){
                return ResponseUtil.ok(obj);
            }else{
                return ResponseUtil.error("文件导入失败");
            }
        }
        return ResponseUtil.error();
    }

    @ApiOperation("离线导入路由表")
    @PostMapping(value = "/uploadRouteTable")
    public Object uploadRouteTable(@RequestParam(value = "file", required = false) MultipartFile file, TopoNodeDto dto) throws IOException {
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/uploadRouteTable.action/";
            url = this.urlConvertUtil.convert(url);
            ByteArrayResource fileAsResource = new ByteArrayResource(file.getBytes()) {
                @Override
                public String getFilename() {
                    return file.getOriginalFilename();
                }
                @Override
                public long contentLength() {
                    return file.getSize();
                }
            };
            MultiValueMap<String, Object> multValueMap = new LinkedMultiValueMap<>();
            multValueMap.add("file", fileAsResource);
            Map<String, Object> map = new BeanMap(dto);
            for(String key : map.keySet()){
                if(map.get(key) != null){
                    multValueMap.set(key, map.get(key));
                }
            }
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.MULTIPART_FORM_DATA);
            headers.set("Authorization", "Bearer " + token);// 设置密钥
            HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity(multValueMap, headers);
            //发起调用
            Object obj =  restTemplate.postForObject(url, requestEntity, Object.class);
            return ResponseUtil.ok(obj);
        }
        return ResponseUtil.error();
    }
    @ApiModelProperty("通过Zabbix获取设备路由表信息-上传到abt")
    @GetMapping("/auto/upload/rout/s")
    public void s(){
        String ip = "192.168.5.176";
        this.zabbixService.createRoutTable(ip);
    }


    @ApiModelProperty("通过Zabbix获取设备路由表信息-上传到abt")
    @GetMapping("/auto/upload/rout/table")
    public Object autoUploadRoutTable(){
        List<Map> maps = this.topoNodeService.queryNetworkElement();
        for (Map map : maps){
            FileInputStream fileInputStream = null;
            MultipartFile multipartFile = null;
            String ip = map.get("ip").toString();
            // 写入路由文件
            this.zabbixService.createRoutTable(ip);
            try {
                String path = ResourceUtils.getURL("classpath:").getPath() + "/static/routs/routTable.conf";
                path = "C:\\Users\\46075\\Desktop\\metoo\\需求记录\\4，策略可视化\\监控系统（Zabbix）\\routTable.conf";
                String routPath = "routTable.conf";
                File file = new File(URLDecoder.decode(path, "utf-8"));
                fileInputStream = new FileInputStream(file);
                multipartFile = new MockMultipartFile(file.getName(),file.getName(),
                        ContentType.APPLICATION_OCTET_STREAM.toString(),fileInputStream);
                SysConfig sysConfig = this.sysConfigService.select();
                String token = sysConfig.getNspmToken();
                if(token != null) {
                    String url = "/topology/node/uploadRouteTable.action/";
                    url = this.urlConvertUtil.convert(url);
                    MultipartFile finalMultipartFile = multipartFile;
                    ByteArrayResource fileAsResource = new ByteArrayResource(finalMultipartFile.getBytes()) {
                        @Override
                        public String getFilename() {
                            return finalMultipartFile.getOriginalFilename();
                        }

                        @Override
                        public long contentLength() {
                            return finalMultipartFile.getSize();
                        }
                    };
                    MultiValueMap<String, Object> multValueMap = new LinkedMultiValueMap<>();
                    multValueMap.add("file", fileAsResource);
                    TopoNodeDto dto = new TopoNodeDto();
                    dto.setDeviceName(map.get("deviceName").toString());
                    dto.setDeviceIp(map.get("ip").toString());
                    dto.setPluginId(map.get("pluginId").toString());
//                    dto.setDeviceName("AAAAAA_HHY-D4");
//                    dto.setDeviceIp("192.168.5.176");
//                    dto.setPluginId("huawei-vrp");
                    Map<String, Object> mapT = new BeanMap(dto);
                    for (String key : mapT.keySet()) {
                        if(mapT.get(key) != null){
                            multValueMap.set(key, mapT.get(key));
                        }
                    }
                    HttpHeaders headers = new HttpHeaders();
                    headers.setContentType(MediaType.MULTIPART_FORM_DATA);
                    headers.set("Authorization", "Bearer " + token);// 设置密钥
                    HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity(multValueMap, headers);
                    //发起调用
                    Object obj = restTemplate.postForObject(url, requestEntity, Object.class);
                    System.out.println(obj);
                    continue;
                }
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return ResponseUtil.ok();
    }
}
