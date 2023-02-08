package com.metoo.nspm.core.manager.integrated.policy;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.TopoPolicyDto;
import com.metoo.nspm.entity.nspm.SysConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RequestMapping("/nspm/test")
@RestController
public class TopoPolocyTest {

    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private NodeUtil nodeUtil;
    private static Map<String, String> navigationMap = new HashMap();

    @RequestMapping("/viewData")
    public Object viewData(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String nspmUrl = sysConfig.getNspmUrl();
        String token = sysConfig.getNspmToken();
        if(nspmUrl != null && token != null){
            String url = nspmUrl + "topology-layer/whale/GET/node/navigation";
            Object navigations = this.nodeUtil.getBody(dto, url, token);
            if(navigations != null){
                String result = JSONObject.toJSONString(navigations);
                JSONObject jsonObject = JSONObject.parseObject(result);
                int navigationSize = jsonObject.size();// 设备数量
                for(int i = 0; i < navigationSize; i++){
                    JSONObject vendors = JSONObject.parseObject(jsonObject.get("0").toString());
                    Map vendorMap = JSONObject.toJavaObject(vendors, Map.class);
                    for(Object key : vendorMap.keySet()){
                        Object value = vendorMap.get(key);
                        JSONObject vendor = JSONObject.parseObject(JSONObject.toJSONString(value));
                        Integer total = Integer.parseInt(vendor.get("total").toString());
                        for(int n = 0; n < total; n++){
                            JSONArray devices = JSONArray.parseArray(vendor.get("data").toString());
                            JSONObject device = JSONObject.parseObject(devices.get(n).toString());
                            navigationMap.put(device.get("deviceName").toString(), device.get("uuid").toString());
                        }
                    }
                }

            }

            String url2 = nspmUrl + "topology-policy/report/policyView/viewData";
            Object result = this.nodeUtil.postFormDataBody(dto, url2, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }




//
//    @RequestMapping("/viewData")
//    public Object viewData(@RequestBody(required = false) TopoPolicyDto dto){
//        SysConfig sysConfig = this.sysConfigService.findSysConfigList();
//        
//        String token = sysConfig.getNspmToken();
//        if(token != null){
//            url = url + "topology-policy/report/policyView/viewData";
//            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
//            return ResponseUtil.ok(result);
//        }
//        return ResponseUtil.error();
//    }

//    @GetMapping(value = "/node/navigation")
//    public Object nodeNavigation(TopoPolicyDto dto){
//        SysConfig sysConfig = this.sysConfigService.findSysConfigList();
//        
//        String token = sysConfig.getNspmToken();
//        if(token != null){
//            url = url + "topology-layer/whale/GET/node/navigation";
//            Object result = this.nodeUtil.getBody(dto, url, token);
//            return ResponseUtil.ok(result);
//        }
//        return ResponseUtil.error();
//    }

}
