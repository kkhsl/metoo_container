package com.metoo.nspm.core.manager.integrated.policy;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.core.utils.CommUtils;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.TopoNodeDto;
import com.metoo.nspm.dto.TopoPolicyDto;
import com.metoo.nspm.entity.nspm.Policy;
import com.metoo.nspm.entity.nspm.SysConfig;
import com.metoo.nspm.entity.nspm.User;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.*;

//@RequiresPermissions("ADMIN:POLICY:MANAGER")
@RequestMapping("/nspm/policy")
@RestController
public class TopoPolicyIntegrateController {

    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private IUserService userService;
    @Autowired
    private NodeUtil nodeUtil;
    @Autowired
    private IPolicyService policyService;
    @Autowired
    private IPolicyStatisticalService policyStatisticalService;
    @Autowired
    private IssuedService ssuedService;

    public static void main(String[] args) {
        String value = "";
        int strLen;
        if (value != null && (strLen = value.length()) != 0) {
            for(int i = 0; i < strLen; ++i) {
                if (!Character.isWhitespace(value.charAt(i))) {
                    System.out.println(false);
                }
            }
        }
    }

    @RequestMapping("/viewData")
    public Object vendors(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            Map map = new HashMap();
            String url = "/topology-policy/report/policyView/viewData";
            List policys = new ArrayList();
            if(dto.getBranchLevel() == null || dto.getBranchLevel().equals("")){
                User currentUser = ShiroUserHolder.currentUser();
                User user = this.userService.findByUserName(currentUser.getUsername());
                dto.setBranchLevel(user.getGroupLevel());
            }
            Object policy = this.nodeUtil.postFormDataBody(dto, url, token);
            JSONObject json = JSONObject.parseObject(policy.toString());
            map.put("total", json.get("total"));
            if(json.get("data") != null){
                JSONArray datas = JSONArray.parseArray(json.get("data").toString());
                for(Object object : datas){
                    JSONObject data = JSONObject.parseObject(object.toString());
                    // 策略总数
                    Integer policyTotal = 0;
                    if(data.get("policyTotalDetail") != null){
                        JSONArray policyTotalDetails = JSONArray.parseArray(data.get("policyTotalDetail").toString());
                        JSONObject policyTotalDetail = JSONObject.parseObject(policyTotalDetails.get(0).toString());
                        Integer aclTotal = 0;
                        Integer natTotal = 0;
                        Integer safeTotal = 0;
                        aclTotal = Integer.parseInt(policyTotalDetail.get("aclTotal").toString());
                        natTotal = Integer.parseInt(policyTotalDetail.get("natTotal").toString());
                        safeTotal = Integer.parseInt(policyTotalDetail.get("safeTotal").toString());
                        policyTotal = aclTotal + natTotal + safeTotal;
                        policyTotalDetail.remove("routTableTotal");
                        policyTotalDetail.remove("staticRoutTotal");
                        policyTotalDetail.remove("policyRoutTotal");
                        data.put("policyTotalDetail", policyTotalDetail);
                    }
                    data.put("policyTotal", policyTotal);
                    // 对象总数
                    Integer objectTotal = data.get("objectTotal") != null ? Integer.parseInt(data.get("objectTotal").toString()) : 0;
                    data.put("objectTotal", objectTotal);
                    Integer policysTotal  = policyTotal + objectTotal;
                    if(policysTotal > 0){
                        // 问题策略数
                        data.put("policyCheckTotal", data.get("policyCheckTotal") != null ? data.get("policyCheckTotal") : 0);
                        // 问题对象数
                        data.put("objectCheckTotal", data.get("objectCheckTotal") != null ? data.get("objectCheckTotal") : 0);
                        // 健康度
                        // 计算问题策略权重
                        double policyGrade = 0;
                        if(data.get("policyCheckTotalDetail") != null){
                            JSONArray detail = JSONArray.parseArray(data.get("policyCheckTotalDetail").toString());
                            if(detail.size() > 0){
                                Map<String, Integer> policyMap = JSONObject.parseObject(detail.get(0).toString(), Map.class);
                                Set<String> keys = policyMap.keySet();
                                Iterator<String> it = keys.iterator();
                                while (it.hasNext()){
                                    String key =  it.next();
                                    // 获取策略权重
                                    double weight = this.policyStatisticalService.getObjByCode(key);
                                    Integer value = policyMap.get(key);
                                    BigDecimal b1 = new BigDecimal(value);
                                    BigDecimal b2 = new BigDecimal(weight);
                                    policyGrade += b1.multiply(b2).doubleValue();
                                }
                            }
                        }
                        // 问题对象策略权重
                        double objectGrade = 0;
                        if(data.get("objectCheckTotalDetail") != null){
                            JSONArray detail = JSONArray.parseArray(data.get("objectCheckTotalDetail").toString());
                            if(detail.size() > 0){
                                Map<String, Integer> policyMap = JSONObject.parseObject(detail.get(0).toString(), Map.class);
                                Set<String> keys = policyMap.keySet();
                                Iterator<String> it = keys.iterator();
                                while (it.hasNext()){
                                    String key =  it.next();
                                    // 获取对象权重
                                    double weight = this.policyStatisticalService.getObjByCode(key);
                                    Integer value = policyMap.get(key);
                                    BigDecimal b1 = new BigDecimal(value);
                                    BigDecimal b2 = new BigDecimal(weight);
                                    objectGrade += b1.multiply(b2).doubleValue();
                                }
                            }
                        }
                        double checkTotal = policyGrade + objectGrade;
                        BigDecimal b1 = new BigDecimal(Double.toString(policysTotal));
                        BigDecimal b2 = new BigDecimal(Double.toString(checkTotal));
                        BigDecimal b3 = b2.divide(b1, 2, BigDecimal.ROUND_HALF_UP);
                        BigDecimal b4 = new BigDecimal(1);
                        if(b3.compareTo(b4) > 0)
                            data.put("grade", new Double(0));
                        else
                            data.put("grade", b4.subtract(b3).doubleValue() * 100);
                    }else{
                        data.put("grade", new Double(100));
                    }
                    // 根据设备ip查询策略检查分析
//                    String check = "/patrol/api/check/statistics/summary/list";
//                    Object checkObject = this.nodeUtil.postFormDataBody(dto, check, token);
//                    JSONObject result = JSONObject.parseObject(checkObject.toString());
//                    if(result.get("code") != null && result.get("code").toString().equals("0")){
//                        if(result.get("content") != null){
//                            JSONObject content = JSONObject.parseObject(result.getString("content"));
//                            JSONArray list = JSONArray.parseArray(content.getString("list"));
//                            for (Object element : list){
//                                JSONObject devices = JSONObject.parseObject(element.toString());
//                                String ip = devices.getString("ip");
//                                if(ip.equalsIgnoreCase(data.getString("ip"))){
//                                    data.put("checkUpdateTime", devices.get("updateTime"));
//                                }
//                            }
//                        }
//                    }
                    policys.add(data);
                }
            }
            map.put("policys", policys);
            return ResponseUtil.ok(map);
        }
        return ResponseUtil.ok();
    }

//    @RequestMapping("/viewData1")
//    public Object vendors1(@RequestBody(required = false) TopoPolicyDto dto){
//        SysConfig sysConfig = this.sysConfigService.select();
//        String token = sysConfig.getNspmToken();
//        if(token != null){
//            String url = "/topology/node/queryNode.action";
//            User currentUser = ShiroUserHolder.currentUser();
//            User user = this.userService.findByUserName(currentUser.getUsername());
//            dto.setBranchLevel(user.getGroupLevel());
//            dto.setDisplay(0);
//            dto.setOrigin(0);
//            dto.setLimit(1000000);
//            JSONArray arrays = new JSONArray();
//            Integer total = 0;
//            if(dto.getType() != null && !dto.getType().equals("")){
//                Object nodes = this.nodeUtil.getBody(dto, url, token);
//                JSONObject object = JSONObject.parseObject(nodes.toString());
//                JSONArray array = JSONArray.parseArray(object.get("data").toString());
//                arrays.addAll(array);
//                total = Integer.parseInt(object.get("total").toString());
//            }else{
//                List<String> types = new ArrayList();
//                types.add("0");
//                types.add("1");
//                for(String type : types){
//                    dto.setType(type);
//                    Object nodes = this.nodeUtil.getBody(dto, url, token);
//                    JSONObject object = JSONObject.parseObject(nodes.toString());
//                    if(object.get("data") != null) {
//                        JSONArray array = JSONArray.parseArray(object.get("data").toString());
//                        arrays.addAll(array);
//                        total += Integer.parseInt(object.get("total").toString());
//                    }
//                }
//            }
//            Map map = new HashMap();
//            map.put("total", total);
//            String url2 = "/topology-policy/report/policyView/viewData";
//            List policys = new ArrayList();
//            for(Object obj : arrays){
//                if(obj != null){
//                    JSONObject node = JSONObject.parseObject(obj.toString());
//                    if(node.get("uuid") != null){
//                        TopoPolicyDto policyDto = new TopoPolicyDto();
//                            policyDto.setCurrentPage(1);
//                            policyDto.setPageSize(dto.getLimit());
//                            policyDto.setVendor(node.get("vendorName").toString());
//                            policyDto.setType(node.get("type").toString());
//                            policyDto.setDeviceUuid(node.get("uuid").toString());
//                            Object policy = this.nodeUtil.postFormDataBody(policyDto, url2, token);
//                            JSONObject json = JSONObject.parseObject(policy.toString());
//                            if(json.get("data") != null){
//                            JSONArray data = JSONArray.parseArray(json.get("data").toString());
//
//                            JSONObject dataJson = JSONObject.parseObject(data.get(0).toString());
//                            dataJson.put("deviceName", dataJson.get("deviceName") != null  ? dataJson.get("deviceName") : "");
//                            // 策略总数
//                            Integer policyTotal = 0;
////                            Integer policyTotal = dataJson.get("policyTotal") != null ? Integer.parseInt(dataJson.get("policyTotal").toString()) : 0;
////                            dataMap.put("policyTotal", policyTotal);
//                            if(dataJson.get("policyTotalDetail") != null){
//                                JSONArray policyTotalDetails = JSONArray.parseArray(dataJson.get("policyTotalDetail").toString());
//                                JSONObject policyTotalDetail = JSONObject.parseObject(policyTotalDetails.get(0).toString());
//                                Integer aclTotal = 0;
//                                Integer natTotal = 0;
//                                Integer safeTotal = 0;
//                                aclTotal = Integer.parseInt(policyTotalDetail.get("aclTotal").toString());
//                                natTotal = Integer.parseInt(policyTotalDetail.get("natTotal").toString());
//                                safeTotal = Integer.parseInt(policyTotalDetail.get("safeTotal").toString());
//                                policyTotal = aclTotal + natTotal + safeTotal;
//                                policyTotalDetail.remove("routTableTotal");
//                                policyTotalDetail.remove("staticRoutTotal");
//                                policyTotalDetail.remove("policyRoutTotal");
//                                dataJson.put("policyTotalDetail", policyTotalDetail);
//                            }
//                            dataJson.put("policyTotal", policyTotal);
//                            // 对象总数
//                            Integer objectTotal = dataJson.get("objectTotal") != null ? Integer.parseInt(dataJson.get("objectTotal").toString()) : 0;
//                            dataJson.put("objectTotal", objectTotal);
//                            Integer policysTotal  = policyTotal + objectTotal;
//                            if(policysTotal > 0){
//                                // 问题策略数
//                                dataJson.put("policyCheckTotal", dataJson.get("policyCheckTotal") != null ? dataJson.get("policyCheckTotal") : 0);
//                                // 问题对象数
//                                dataJson.put("objectCheckTotal", dataJson.get("objectCheckTotal") != null ? dataJson.get("objectCheckTotal") : 0);
//                                // 健康度
//                                // 计算问题策略权重
//                                double policyGrade = 0;
//                                if(dataJson.get("policyCheckTotalDetail") != null){
//                                    JSONArray detail = JSONArray.parseArray(dataJson.get("policyCheckTotalDetail").toString());
//                                    if(detail.size() > 0){
//                                        Map<String, Integer> policyMap = JSONObject.parseObject(detail.get(0).toString(), Map.class);
//                                        Set<String> keys = policyMap.keySet();
//                                        Iterator<String> it = keys.iterator();
//                                        while (it.hasNext()){
//                                            String key =  it.next();
//                                            // 获取策略权重
//                                            double weight = this.policyStatisticalService.getObjByCode(key);
//                                            Integer value = policyMap.get(key);
//                                            BigDecimal b1 = new BigDecimal(value);
//                                            BigDecimal b2 = new BigDecimal(weight);
//                                            policyGrade += b1.multiply(b2).doubleValue();
//                                        }
//                                    }
//                                }
//                                // 问题对象策略权重
//                                double objectGrade = 0;
//                                if(dataJson.get("objectCheckTotalDetail") != null){
//                                    JSONArray detail = JSONArray.parseArray(dataJson.get("objectCheckTotalDetail").toString());
//                                    if(detail.size() > 0){
//                                        Map<String, Integer> policyMap = JSONObject.parseObject(detail.get(0).toString(), Map.class);
//                                        Set<String> keys = policyMap.keySet();
//                                        Iterator<String> it = keys.iterator();
//                                        while (it.hasNext()){
//                                            String key =  it.next();
//                                            // 获取对象权重
//                                            double weight = this.policyStatisticalService.getObjByCode(key);
//                                            Integer value = policyMap.get(key);
//                                            BigDecimal b1 = new BigDecimal(value);
//                                            BigDecimal b2 = new BigDecimal(weight);
//                                            objectGrade += b1.multiply(b2).doubleValue();
//                                        }
//                                    }
//                                }
//                                double checkTotal = policyGrade + objectGrade;
//                                BigDecimal b1 = new BigDecimal(Double.toString(policysTotal));
//                                BigDecimal b2 = new BigDecimal(Double.toString(checkTotal));
//                                BigDecimal b3 = b2.divide(b1, 2, BigDecimal.ROUND_HALF_UP);
//                                BigDecimal b4 = new BigDecimal(1);
//                                if(b3.compareTo(b4) > 0)
//                                    dataJson.put("policyCheckTotal", 0);
//                                    else
//                                    dataJson.put("policyCheckTotal", b4.subtract(b3).doubleValue() * 100);
//                                policys.add(dataJson);
//                            }
//                        }
//                    }
//                }
//            }
//            map.put("policys", policys);
//            return ResponseUtil.ok(map);
//        }
//        return ResponseUtil.ok();
//    }

//    @RequestMapping("/viewData")
//    public Object vendors(@RequestBody(required = false) TopoPolicyDto dto){
//        SysConfig sysConfig = this.sysConfigService.select();
//
//        String token = sysConfig.getNspmToken();
//        if(token != null){
//            String nodeString url = "/topology/node/queryNode.action";
//            User currentUser = ShiroUserHolder.currentUser();
//            User user = this.userService.findByUserName(currentUser.getUsername());
//            dto.setBranchLevel(user.getGroupLevel());
//            dto.setDisplay(0);
//            dto.setOrigin(0);
//            dto.setLimit(1000000);
//            dto.setState("1");
//            JSONArray arrays = new JSONArray();
//            Integer total = 0;
//            if(dto.getType() != null && !dto.getType().equals("")){
//                Object nodes = this.nodeUtil.getBody(dto, nodeUrl, token);
//                JSONObject object = JSONObject.parseObject(nodes.toString());
//                JSONArray array = JSONArray.parseArray(object.get("data").toString());
//                arrays.addAll(array);
//                total = Integer.parseInt(object.get("total").toString());
//            }else{
//                List<String> types = new ArrayList();
//                types.add("0");
//                types.add("1");
//                for(String type : types){
//                    dto.setType(type);
//                    Object nodes = this.nodeUtil.getBody(dto, nodeUrl, token);
//                    JSONObject object = JSONObject.parseObject(nodes.toString());
//                    if(object.get("data") != null) {
//                        JSONArray array = JSONArray.parseArray(object.get("data").toString());
//                        arrays.addAll(array);
//                        total += Integer.parseInt(object.get("total").toString());
//                    }
//                }
//            }
//                Map map = new HashMap();
//                map.put("total", total);
//                String policyString url = "/topology-policy/report/policyView/viewData";
//                List policys = new ArrayList();
//                for(Object obj : arrays){
//                    if(obj != null){
//                        JSONObject node = JSONObject.parseObject(obj.toString());
//                        if(node.get("uuid") != null){
//                            Map dataMap = new HashMap();
//                            navigationMap.put(node.get("ip").toString(), node.get("uuid").toString());
//                            TopoPoviewDataviewDatalicyDto policyDto = new TopoPolicyDto();
//                            policyDto.setCurrentPage(1);
//                            policyDto.setPageSize(dto.getLimit());
//                            policyDto.setVendor(node.get("vendorName").toString());
//                            policyDto.setType(node.get("type").toString());
//                            policyDto.setDeviceUuid(node.get("uuid").toString());
//                            Object policy = this.nodeUtil.postFormDataBody(policyDto, policyUrl, token);
//                            JSONObject json = JSONObject.parseObject(policy.toString());
//                            if(json.get("data") != null){
//                                JSONArray data = JSONArray.parseArray(json.get("data").toString());
//                                Double score = this.policyService.getGrade(node.get("uuid").toString());
//                                JSONObject dataJson = JSONObject.parseObject(data.get(0).toString());
//                                dataJson.put("policyCheckTotal", score);
//                                policys.add(dataJson);
//                                dataMap.put("policyCheckTotal", score);
//                            }else{
//                                dataMap.put("policyCheckTotal", 0);
//                            }
//                        }
//                    }
//                }
//                map.put("policys", policys);
//                return ResponseUtil.ok(map);
//        }
//        return ResponseUtil.ok();
//    }



//    @RequestMapping("/viewData")
//    public Object viewData(@RequestBody(required = false) TopoPolicyDto dto){
//        SysConfig sysConfig = this.sysConfigService.select();
//        String nspmUrl = sysConfig.getNspmUrl();
//        String token = sysConfig.getNspmToken();
//        if(nspmUrl != null && token != null){
//            if(dto.getVendor() == null || dto.getVendor().equals("")){
//                String url = nspmUrl + "/topology/node/getNavigation.action";
//                User currentUser = ShiroUserHolder.currentUser();
//                User user = this.userService.findByUserName(currentUser.getUsername());
//                dto.setBranchLevel(user.getGroupLevel());
//                String type = dto.getType();
//                dto.setType(null);
//                Object navigations = this.nodeUtil.getBody(dto, url, token);
//                List<String> vendorList = new ArrayList<String>();
//                if(navigations != null){
//                    String result = JSONObject.toJSONString(navigations);
//                    JSONObject devices = JSONObject.parseObject(result);
//                    if(!devices.isEmpty()){
//                        List<Object> list = new ArrayList<Object>();
//                        for(String device : devices.keySet()){
//                            if(type != null){
//                                if(device.equals(type)){
//                                    JSONObject vendors = JSONObject.parseObject(devices.get(device).toString());
//                                    for(String vendor : vendors.keySet()){
//                                        dto.setVendor(vendor);
//                                        dto.setType(type);
//                                        String url2 = nspmUrl + "/topology-policy/report/policyView/viewData";
//                                        Object policy = this.nodeUtil.postFormDataBody(dto, url2, token);
//                                        JSONObject json = JSONObject.parseObject(policy.toString());
//                                        List array = Arrays.asList(json.get("data"));
//                                        list.addAll(array);
//                                    }
//
//                                }
//                            }else{
//                                JSONObject vendors = JSONObject.parseObject(devices.get(device).toString());
//                                for(String vendor : vendors.keySet()){
//                                    dto.setVendor(vendor);
//                                    dto.setType(type);
//                                    String url2 = nspmUrl + "/topology-policy/report/policyView/viewData";
//                                    Object policy = this.nodeUtil.postFormDataBody(dto, url2, token);
//                                    JSONObject json = JSONObject.parseObject(policy.toString());
//                                    List array = Arrays.asList(json.get("data"));
//                                    list.addAll(array);
//                                }
//
//                            }
//                        }
//                        return ResponseUtil.ok(list);
//                    }
//                }
//            }else{
//                String url2 = nspmUrl + "/topology-policy/report/policyView/viewData";
//                Object result = this.nodeUtil.postFormDataBody(dto, url2, token);
//                return ResponseUtil.ok(result);
//            }
//        }
//        return ResponseUtil.error();
//    }


//    @RequestMapping("/viewData")
//    public Object viewData(@RequestBody(required = false) TopoPolicyDto dto){
//        SysConfig sysConfig = this.sysConfigService.select();
//        String nspmUrl = sysConfig.getNspmUrl();
//        String token = sysConfig.getNspmToken();
//        String url2 = nspmUrl + "/topology-policy/report/policyView/viewData";
//        Object result = this.nodeUtil.postFormDataBody(dto, url2, token);
//        return ResponseUtil.ok(result);
//    }

//    @RequestMapping("/viewData")
//    public Object viewData(@RequestBody(required = false) TopoPolicyDto dto){
//        SysConfig sysConfig = this.sysConfigService.select();
//        String nspmUrl = sysConfig.getNspmUrl();
//        String token = sysConfig.getNspmToken();
//        if(nspmUrl != null && token != null){
//            String url = nspmUrl + "/topology-layer/whale/GET/node/navigation";
//            User currentUser = ShiroUserHolder.currentUser();
//            User user = this.userService.findByUserName(currentUser.getUsername());
//            dto.setBranchLevel(user.getGroupLevel());
//            Object navigations = this.nodeUtil.getBody(dto, url, token);
//            List<String> vendorList = new ArrayList<String>();
//            if(navigations != null){
//                String result = JSONObject.toJSONString(navigations);
//                JSONObject jsonObject = JSONObject.parseObject(result);
//                int navigationSize = jsonObject.size();// 设备数量
//                for(int i = 0; i < 6; i++){
//                    if(jsonObject.get(i) != null){
//                        if(i > 1){
//                            break;
//                        }
//                        JSONObject vendors = JSONObject.parseObject(jsonObject.get(i).toString());
//                        boolean flag = Integer.parseInt(dto.getType()) == i ? true : false;
//                        Map vendorMap = JSONObject.toJavaObject(vendors, Map.class);
//                        for(Object key : vendorMap.keySet()){
//                            Object value = vendorMap.get(key);
//                            if(flag){
//                                vendorList.add(key.toString());
//                            }
//                            JSONObject vendor = JSONObject.parseObject(JSONObject.toJSONString(value));
//                            Integer total = Integer.parseInt(vendor.get("total").toString());
//                            for(int n = 0; n < total; n++){
//                                JSONArray devices = JSONArray.parseArray(vendor.get("data").toString());
//                                JSONObject device = JSONObject.parseObject(devices.get(n).toString());
//                                navigationMap.put(device.get("ip").toString(), device.get("uuid").toString());
//                                System.out.println(device.get("pluginId").toString() + "/" +  device.get("vendorName").toString() + "/" + device.get("ip").toString());
//                            }
//                        }
//                    }
//                }
//            }
//            if(vendorList.size() > 0){
//                List<Object> list = new ArrayList<Object>();
//                for(String vendors : vendorList){
//                    String vendor = vendors;
//                    dto.setVendor(vendor);
//                    String url2 = nspmUrl + "/topology-policy/report/policyView/viewData";
//                    Object result = this.nodeUtil.postFormDataBody(dto, url2, token);
//                    JSONObject json = JSONObject.parseObject(result.toString());
//                    List array = Arrays.asList(json);
//                    list.addAll(array);
//                }
//                return ResponseUtil.ok(list);
//            }
//            return ResponseUtil.ok();
//        }
//        return ResponseUtil.error();
//    }

    @GetMapping(value = "/node/navigation")
    public Object nodeNavigation(TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            User currentUser = ShiroUserHolder.currentUser();
            User user = this.userService.findByUserName(currentUser.getUsername());
            dto.setBranchLevel(user.getGroupLevel());
            String url = "/topology-layer/whale/GET/node/navigation";
            Object result = this.nodeUtil.getBody(dto, url, token);
            Map map = JSONObject.parseObject(result.toString(), Map.class);
            Map resultMap = new HashMap();
            resultMap.put(0, map.get("0"));
            resultMap.put(1, map.get("1"));
//            if(map.get("3") != null){
//                Map vendor = JSONObject.parseObject(map.get("3").toString(), Map.class);
//                for (Object key : vendor.keySet()){
//                    if(key.toString().equals("安博通")){
//                        vendor.put("觅通", vendor.get(key.toString()));
//                        vendor.remove("安博通");
//                    }
//                }
//                resultMap.put("3", vendor);
//            }
            return ResponseUtil.ok(resultMap);
        }
        return ResponseUtil.error();
    }

    @GetMapping("/getUuid")
    public Object getUuid(String ip){
        if(ip != null   ){
            SysConfig sysConfig = this.sysConfigService.select();
            String token = sysConfig.getNspmToken();
            if(token != null){
                TopoNodeDto dto = new TopoNodeDto();
                String url = "topology/node/queryNode.action";
                User currentUser = ShiroUserHolder.currentUser();
                User user = this.userService.findByUserName(currentUser.getUsername());
                dto.setBranchLevel(user.getGroupLevel());
                dto.setFilter(ip);
                dto.setStart(1);
                dto.setLimit(20);
                dto.setDisplay(0);
                dto.setOrigin("0");
                Object result = this.nodeUtil.getBody(dto, url, token);
                JSONObject object = JSONObject.parseObject(result.toString());
                if(object.get("data") != null){
                    JSONArray arrays = JSONArray.parseArray(object.get("data").toString());
                    for(Object array : arrays){
                        JSONObject data = JSONObject.parseObject(array.toString());
                        if(data.get("ip").toString().equals(ip)){
                            return ResponseUtil.ok(data/*.get("uuid")*/);
                        }
                    }
                    return ResponseUtil.ok();
                }
            }
        }
        return ResponseUtil.badArgument();
    }

    @ApiOperation("合并策略（详情）")
    @PostMapping(value = "/rule-list")
    public Object ruleList(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/policy/filter-list/rout/rule-list";
            Object object = this.nodeUtil.postFormDataBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("success") != null){
                if(result.get("success").toString().equals("false")){
                    return ResponseUtil.error(result.get("message").toString());
                }
            }
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("源Ip、目的Ip、服务(对象信息)")
    @RequestMapping("/query-object-detail")
    public Object queryObjectDetail(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/device/query-object-detail";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @RequestMapping("/batch-skip-check")
    public Object batchSkipCheck(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/policy/batch-skip-check";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }



    @ApiOperation("策略集")
    @PostMapping(value = "/filter-list")
    public Object filterList(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/policy/filter-list";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略集(静态路由)")
    @PostMapping(value = "/filter-list/static-rout")
    public Object filterListStaticRout(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/policy/filter-list/static-rout";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略集(静态路由)")
    @PostMapping(value = "/filter-list/rout-table")
    public Object filterListRoutTable(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/policy/filter-list/rout-table";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("安全域")
        @PostMapping(value = "/listDeviceZone")
    public Object listDeviceZone(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/risk/api/alarm/zone/listDeviceZone";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }


    @ApiOperation("设备接口")
    @PostMapping(value = "/listDeviceInterface")
    public Object listDeviceInterface(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/risk/api/alarm/zone/listDeviceInterface";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("详情")
    @PostMapping(value = "/raw-config")
    public Object rawConfig(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/device/raw-config";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("备注")
    @PostMapping(value = "/remark/get")
    public Object remarkGet(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/policy/remark/get";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("备注")
    @PostMapping(value = "/remark/save")
    public Object remarkSave(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/policy/remark/save";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("安全域接口")
    @PostMapping(value = "/listDeviceZoneInterface")
    public Object listDeviceZoneInterface(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/risk/api/alarm/zone/listDeviceZoneInterface";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("对象分布")
    @PostMapping(value = "/object-list-pie")
    public Object objectListPie(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/report/policy/object-list-pie";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("对象列表")
    @PostMapping(value = "/object-list")
    public Object objectList(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/device/object-list";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略列表-对象列表-查询")
    @PostMapping(value = "/topology-policy/device/search-address")
    public Object searchAddress(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/device/search-address";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略列表-对象列表-查询")
    @PostMapping(value = "/topology-policy/device/search-service")
    public Object searchService(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/device/search-service";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }




    @ApiOperation("策略优化列表")
    @PostMapping(value = "/check")
    public Object check(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/policy/check";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略优化统计")
    @PostMapping(value = "/policy-check-pie")
    public Object policyCheckPie(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/report/policy/policy-check-pie";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("ACL未调用（未调用策略集）")
    @PostMapping(value = "/unrefAclList")
    public Object unrefAclList(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/policy/unrefAclList";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("合并策略（详情）")
    @PostMapping(value = "/check/primary")
    public Object checkPrimary(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/policy/check/primary";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略优化-对象统计")
    @PostMapping(value = "/object-check-pie")
    public Object objectCheckPie(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/report/policy/object-check-pie";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略优化-对象优化")
    @PostMapping(value = "/object/check")
    public Object objectCheck(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/object/check/";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("命中收敛-厂商")
    @PostMapping(value = "/listVendorName")
    public Object listVendorName(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/hit/count/listVendorName";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("命中收敛-内网ip地址管理")
    @PostMapping(value = "/intranetIpList")
    public Object intranetIpList(@RequestBody(required = false) TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/hit/logConfig/intranetIpList";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("命中收敛-任务列表")
    @PostMapping(value = "/listDevNodeLogConfig")
    public Object listDevNodeLogConfig(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/hit/count/listDevNodeLogConfig";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("命中收敛-内网ip地址管理-保存")
    @PostMapping(value = "/saveIntranetIp")
    public Object saveIntranetIp(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/hit/logConfig/saveIntranetIp";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("命中收敛-内网ip地址管理-保存")
    @PostMapping(value = "/logConfigList")
    public Object logConfigList(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/hit/logConfig/list";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("命中收敛-内网ip地址管理-保存")
    @RequestMapping(value = "/logConfigEdit")
    public Object logConfigEdit(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/hit/logConfig/edit";
            Object object = this.nodeUtil.postFormDataBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("status").toString().equals("0")){
                return ResponseUtil.ok(result);
            }else{
                return ResponseUtil.error(result.get("errmsg").toString());
            }
        }
        return ResponseUtil.error();
    }


    @ApiOperation("命中收敛-利用率-策略信息")
    @PostMapping(value = "/combing/api/hit/count/getInfoByDeviceUuid")
    public Object getInfoByDeviceUuid(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/hit/count/getInfoByDeviceUuid";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("命中收敛-利用率-策略收敛分析")
    @PostMapping(value = "/combing/api/hit/count/analysis")
    public Object analysis(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/hit/count/analysis";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("命中收敛-利用率-源地址命中")
    @PostMapping(value = "/combing/api/hit/count/findSrcIpHitCountList")
    public Object findSrcIpHitCountList(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/hit/count/findSrcIpHitCountList";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("命中收敛-利用率-目的地址命中")
    @PostMapping(value = "/combing/api/hit/count/findDstIpHitCountList")
    public Object findDstIpHitCountList(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/hit/count/findDstIpHitCountList";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("命中收敛-利用率-目的端口命中")
    @PostMapping(value = "/combing/api/hit/count/findDstPortHitCountList")
    public Object findDstPortHitCountList(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/hit/count/findDstPortHitCountList";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("命中收敛-利用率-策略Id列表、命中数")
    @PostMapping(value = "/combing/api/hit/count/hitCountList")
    public Object hitCountList(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/hit/count/hitCountList";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }


    @ApiOperation("命中收敛-利用率-SrcIp 命中CountLis树形")
    @PostMapping(value = "/combing/api/hit/count/findSrcIpHitCountTree")
    public Object findSrcIpHitCountTree(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/hit/count/findSrcIpHitCountTree";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("命中收敛-利用率-DstIp 命中CountLis树形")
    @PostMapping(value = "/combing/api/hit/count/findDstIpHitCountTree")
    public Object findDstIpHitCountTree(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/hit/count/findDstIpHitCountTree";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }


    @ApiOperation("命中收敛-标记忽略检查")
    @PostMapping(value = "/skipCheck")
    public Object skipCheck(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/policy/skip-check";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("命中收敛-利用率-命中收敛查任务结果")
    @PostMapping(value = "/combing/api/suggest/result/listByPolicyUuid")
    public Object listByPolicyUuid(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/suggest/result/listByPolicyUuid";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("命中收敛-利用率-生成命令行")
    @PostMapping(value = "/combing/api/hit/count/new-policy-push")
    public Object new_policy_push(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/hit/count/new-policy-push";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("命中收敛-利用率-下载命令行")
    @PostMapping(value = "/combing/api/hit/count/downloadCommand")
    public Object downloadCommand(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url =  "/combing/api/hit/count/downloadCommand";
            Map map = new HashMap();
            map.put("command", dto.getCommand());
            map.put("deviceName", dto.getDeviceName());
            return this.nodeUtil.downloadPost(map, url, token);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("命中收敛-利用率-开启梳理")
    @PostMapping(value = "/combing/api/suggest/task/add")
    public Object add(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/suggest/task/add";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略梳理-任务列表")
    @PostMapping(value = "/combing/api/suggest/task/list")
    public Object taskList(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/suggest/task/list";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略梳理-新建-设备列表")
    @PostMapping(value = "/combing/api/suggest/task/getDevNode")
    public Object getDevNode(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/suggest/task/getDevNode";
            if(dto.getBranchLevel() == null || dto.getBranchLevel().equals("")){
                User currentUser = ShiroUserHolder.currentUser();
                User user = this.userService.findByUserName(currentUser.getUsername());
                dto.setBranchLevel(user.getGroupLevel());
            }
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略梳理-新建-设备列表-选择")
    @PostMapping(value = "/combing/api/suggest/task/checkDevLog")
    public Object checkDevLog(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/suggest/task/checkDevLog";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

//    @ApiOperation("策略梳理-新建-保存")
//    @PostMapping(value = "/combing/api/suggest/task/add")
//    public Object taskAdd(@RequestBody TopoPolicyDto dto){
//        SysConfig sysConfig = this.sysConfigService.select();
//
//        String token = sysConfig.getNspmToken();
//        if(token != null){
//            String url = "/combing/api/suggest/task/add";
//            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
//            return ResponseUtil.ok(result);
//        }
//        return ResponseUtil.error();
//    }

    @ApiOperation("策略梳理-新建-删除")
    @PostMapping(value = "/combing/api/suggest/task/delete")
    public Object delete(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/suggest/task/delete";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略梳理-下载")
    @GetMapping(value="/combing/api/suggest/result/export")
    public Object export(@RequestParam("taskId") String taskId){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url =  "/combing/api/suggest/result/export";
            Map map = new HashMap();
            map.put("taskId", taskId);
            return this.nodeUtil.download(map, url, token);
        }
        return ResponseUtil.error();
    }



    @ApiOperation("策略梳理-任务-详情")
    @PostMapping(value = "/combing/api/suggest/result/list")
    public Object resultList(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/suggest/result/list";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略梳理-任务-梳理")
    @PostMapping(value = "/combing/api/suggest/task/again")
    public Object again(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/suggest/task/again";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略梳理-任务-停止梳理")
    @PostMapping(value = "/combing/api/suggest/threadPool/stopTask")
    public Object stopTask(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/suggest/threadPool/stopTask";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略梳理-任务-日志")
    @PostMapping(value = "/combing/api/suggest/rawlog/findList")
    public Object findList(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/suggest/rawlog/findList";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略梳理-任务-日志-查找设备")
    @PostMapping(value = "/combing/api/suggest/rawlog/findDeviceIsVsys")
    public Object findDeviceIsVsys(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/combing/api/suggest/rawlog/findDeviceIsVsys";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略对比-列表")
    @PostMapping(value = "/topology-policy/policy/getPolicyCompareTaskList")
    public Object getPolicyCompareTaskList(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/policy/getPolicyCompareTaskList";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略对比-新增")
    @PostMapping(value = "/topology-policy/policy/createPolicyCompareTask")
    public Object createPolicyCompareTask(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/policy/createPolicyCompareTask";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略对比-删除")
    @PostMapping(value = "/topology-policy/policy/deletePolicyCompareTask")
    public Object deletePolicyCompareTask(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/policy/deletePolicyCompareTask";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略对比-详情")
    @PostMapping(value = "/topology-policy/policy/policyCompareTaskDetail")
    public Object policyCompareTaskDetail(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/policy/policyCompareTaskDetail";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略对比-安全策略/静态路由")
    @PostMapping(value = "/topology-policy/policy/policyCompare/list")
    public Object policyCompareList(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/policy/policyCompare/list";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("策略对比-统计信息")
    @PostMapping(value = "/topology-policy/policy/policyCompare/statisticalInformation")
    public Object statisticalInformation(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology-policy/policy/policyCompare/statisticalInformation";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

//    @ApiOperation("策略优化-是否加入下发队列")
//    @PostMapping(value = "/push/task/addpushtasks")
//    public Object addPushShtasks(@RequestBody TopoPolicyDto dto){
//        SysConfig sysConfig = this.sysConfigService.select();
//
//        String token = sysConfig.getNspmToken();
//        if(token != null){
//            String addString url = "/push/task/addpushtasks";
//            User currentUser = ShiroUserHolder.currentUser();
//            User user = this.userService.findByUserName(currentUser.getUsername());
//            JSONObject dtoJson = (JSONObject) JSONObject.toJSON(dto);
//            if(dtoJson != null){
//                JSONArray arrays = JSONArray.parseArray(dtoJson.get("tasks").toString());
//                if(arrays.size() > 0){
//                    JSONObject json = JSONObject.parseObject(arrays.get(0).toString());
//                    if(dto.getFrom().equals("2")){
//                        // "" ""
//                        json.put("command", "##" + "policy " + dto.getPolicyId() +"|"+ user.getUsername() + "`~\n" + json.get("command"));
//                    }else if(dto.getFrom().equals("17")){
//                        json.put("command", "##" + "object" + dto.getName() +"|"+ user.getUsername() + "`~\n" + json.get("command"));
//                    }
//                    arrays.clear();
//                    arrays.add(json);
//                    dto.setTasks(arrays);
//                    Object result = this.nodeUtil.postFormDataBody(dto, addUrl, token);
//                    JSONObject resultJ = JSONObject.parseObject(result.toString());
//                    if(resultJ.get("status").toString().equals("0")){
//                        // 执行完成 保存策略信息
//                        // 策略优化 查询策略信息
//                        if(dto.getFrom().equals("2")){
//                            TopoPolicyDto policyDto = new TopoPolicyDto();
//                            policyDto.setCurrentPage(dto.getCurrentPage());
//                            policyDto.setPageSize(dto.getPageSize());
//                            policyDto.setDeviceUuid(dto.getDeviceUuid());
//                            policyDto.setType(dto.getType());
//                            String policyString url = "/topology-policy/policy/check";
//                            Object policyResult = this.nodeUtil.postFormDataBody(policyDto, policyUrl, token);
//                            JSONObject resultJson = JSONObject.parseObject(policyResult.toString());
//                            if(resultJson.get("data") != null){
//                                JSONArray poliscyArrays = JSONArray.parseArray(resultJson.get("data").toString());
//                                if(poliscyArrays.size() > 0){
//                                    for(Object array : poliscyArrays){
//                                        JSONObject data = JSONObject.parseObject(array.toString());
//                                        if(data.get("relatedPolicyId").toString().equals(dto.getPolicyId())){
//                                            // 查询当前策略是否存在，不存在则更新
//                                            Policy policy = new Policy();
//                                            policy.setParentId(dto.getPolicyId());
//                                            policy.setDeviceUuid(dto.getDeviceUuid());
//                                            List<Policy> policys = this.policyService.getObjByMap(policy);
//                                            if(policys.size() > 0){
//                                                int i = this.policyService.delete(policy);
//                                            }
//                                            policys = this.policyService.getObjByMap(policy);
//                                            if(policys.size() == 0){                                            // 插入数据库
//                                                JSONArray details = JSONArray.parseArray(data.get("detailList").toString());
//                                                for(Object obj : details){
//                                                    Map map = JSON.parseObject(obj.toString(), Map.class);
//                                                    map.put("parentId", dto.getPolicyId());
//                                                    map.put("policyType", "RuleCheck_1");
//                                                    map.put("deviceUuid", data.get("deviceUuid"));
//                                                    this.policyService.save(map);
//                                                }
//                                            }
//                                        }
//                                    }
//                                }
//                            }
//                        }else if(dto.getFrom().equals("17")){ // 对象优化
//                            TopoPolicyDto policyDto = new TopoPolicyDto();
//                            policyDto.setCurrentPage(dto.getCurrentPage());
//                            policyDto.setPageSize(dto.getPageSize());
//                            policyDto.setDeviceUuid(dto.getDeviceUuid());
//                            policyDto.setType(dto.getType());
//                            policyDto.setObjectType(dto.getObjectType());
//                            String objectString url = "/topology-policy/object/check";
//                            Object objectResult = this.nodeUtil.postFormDataBody(policyDto, objectUrl, token);
//                            JSONObject objects = JSONObject.parseObject(objectResult.toString());
//                            if(objects.get("data") != null){
//                                JSONArray objectArray = JSONArray.parseArray(objects.get("data").toString());
//                                if(objectArray.size() > 0){
//                                    for(Object array : objectArray){
//                                        JSONObject data = JSONObject.parseObject(array.toString());
//                                        if(data.get("name").toString().equals(dto.getName())){
//                                            // 执行批量删除
//                                            Policy policy = new Policy();
//                                            policy.setName(dto.getName());
//                                            policy.setDeviceUuid(dto.getDeviceUuid());
//                                            List<Policy> policys = this.policyService.getObjByMap(policy);
//                                            if(policys.size() > 0){
//                                                int i = this.policyService.delete(policy);
//                                            }
//                                            // 查询当前策略是否存在，不存在则更新
//                                            policys = this.policyService.getObjByMap(policy);
//                                            if(policys.size() == 0){
//                                                // 插入数据库
//                                                Map map = JSON.parseObject(data.toString(), Map.class);
//                                                map.put("policyType", "RC_EMPTY_OBJECT");
//                                                this.policyService.save(map);
//                                                break;
//                                            }
//                                        }
//                                    }
//                                }
//                            }
//
//                        }
//                    }
//                    return ResponseUtil.ok(result);
//                }
//            }
//            return ResponseUtil.badArgument();
//        }
//        return ResponseUtil.error();
//    }

    @ApiOperation("策略优化-是否加入下发队列")
    @PostMapping(value = "/push/task/addpushtasks")
    public Object addPushShtasks(@RequestBody TopoPolicyDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null) {
            String url = "/push/task/addpushtasks";
            if (dto != null) {
                User currentUser = ShiroUserHolder.currentUser();
                User user = this.userService.findByUserName(currentUser.getUsername());
                if(dto.getBranchLevel() == null || dto.getBranchLevel().equals("")){
                    dto.setBranchLevel(user.getGroupLevel());
                }
                if(dto.getTasks().size() > 0){
                    List list = dto.getTasks();
                    Object obj = list.get(0);
                    String str = JSONObject.toJSONString(obj);
                    JSONObject json = JSONObject.parseObject(str);
                    json.put("userName",user.getUsername());
                    dto.getTasks().remove(0);
                    dto.getTasks().add(json);
                }
                Object object = this.nodeUtil.postFormDataBody(dto, url, token);
                JSONObject result = JSONObject.parseObject(object.toString());
                if(result.get("status").toString().equals("0")) {
                    // 更新字符状态
//                    Invisible invisible = new Invisible();
//                    invisible.setName(invisibleName);
//                    invisible.setStatus(1);
//                    this.invisibleService.update(invisible);
                    // 执行完成 保存策略信息
                    // 策略优化 查询策略信息
                    if (dto.getFrom().equals("2")) {
                        TopoPolicyDto policyDto = new TopoPolicyDto();
                        policyDto.setCurrentPage(dto.getCurrentPage());
                        policyDto.setPageSize(dto.getPageSize());
                        policyDto.setDeviceUuid(dto.getDeviceUuid());
                        policyDto.setType(dto.getType());
                        String url2 = "/topology-policy/policy/check";
                        Object policyResult = this.nodeUtil.postFormDataBody(policyDto, url2, token);
                        JSONObject resultJson = JSONObject.parseObject(policyResult.toString());
                        if (resultJson.get("data") != null) {
                            JSONArray poliscyArrays = JSONArray.parseArray(resultJson.get("data").toString());
                            if (poliscyArrays.size() > 0) {
                                for (Object array : poliscyArrays) {
                                    JSONObject data = JSONObject.parseObject(array.toString());
                                    if(data.get("index").toString().equals(dto.getIndex().toString())){
                                        Policy policy = new Policy();
                                        String random = CommUtils.randomString(6);
                                        policy.setParentName(random);
                                        policy.setDeviceUuid(dto.getDeviceUuid());
                                        JSONArray details = JSONArray.parseArray(data.get("detailList").toString());
                                        for (Object obj : details) {
                                            Map map = JSON.parseObject(obj.toString(), Map.class);
                                            map.put("parentName", random);
                                            map.put("policyType", "RuleCheck_1");
                                            map.put("deviceUuid", data.get("deviceUuid"));
                                            map.put("deviceName", data.get("deviceName"));
                                            map.put("deviceType", data.get("deviceType"));
                                            this.policyService.save(map);
                                        }
                                        // 更新策略信息，添加工单号
                                        List<Policy> policysNew = this.policyService.getObjByMap(policy);
                                        this.ssuedService.createOrder(user.getUsername(), dto.getFrom(), policysNew);
                                        break;
                                    }
                                }
                            }
                        }

                    }else if(dto.getFrom().equals("17")){ // 对象优化
                        TopoPolicyDto policyDto = new TopoPolicyDto();
                        policyDto.setCurrentPage(dto.getCurrentPage());
                        policyDto.setPageSize(dto.getPageSize());
                        policyDto.setDeviceUuid(dto.getDeviceUuid());
                        policyDto.setType(dto.getType());
                        policyDto.setObjectType(dto.getObjectType());
                        String url2 = "/topology-policy/object/check";
                        Object objectResult = this.nodeUtil.postFormDataBody(policyDto, url2, token);
                        JSONObject objects = JSONObject.parseObject(objectResult.toString());
                        if(objects.get("data") != null){
                            JSONArray objectArray = JSONArray.parseArray(objects.get("data").toString());
                            if(objectArray.size() > 0){
                                for(Object array : objectArray){
                                    JSONObject data = JSONObject.parseObject(array.toString());
                                    if(data.get("index").toString().equals(dto.getIndex().toString())){
                                        // 执行批量删除
                                        String random = CommUtils.randomString(6);
                                        Policy policy = new Policy();
                                        policy.setParentName(random);
                                        policy.setDeviceUuid(dto.getDeviceUuid());
//                                          插入数据库
                                        Map map = JSON.parseObject(data.toString(), Map.class);
                                        map.put("policyType", "RC_EMPTY_OBJECT");
                                        map.put("parentName", random);
                                        this.policyService.save(map);
                                        // 更新策略信息，添加工单号
                                        List<Policy> policysNew = this.policyService.getObjByMap(policy);
                                        this.ssuedService.createOrder(user.getUsername(), dto.getFrom(), policysNew);
                                        break;
                                    }

                                }
                            }
                        }

                    }
                    return ResponseUtil.ok();
                }
                // ============================
                return ResponseUtil.error();
            }
            return ResponseUtil.badArgument();
        }
        return ResponseUtil.badArgument();
    }

//    @ApiOperation("策略优化-是否加入下发队列")
//    @PostMapping(value = "/push/task/addpushtasks")
//    public Object addPushShtasks(@RequestBody TopoPolicyDto dto){
//        SysConfig sysConfig = this.sysConfigService.select();
//
//        String token = sysConfig.getNspmToken();
//        if(token != null){
//            String url = "/push/task/addpushtasks";
//            JSONObject dtoJson = (JSONObject) JSONObject.toJSON(dto);
//            if(dtoJson != null){
//                JSONArray arrays = JSONArray.parseArray(dtoJson.get("tasks").toString());
//                if(arrays.size() > 0){
//                    JSONObject json = JSONObject.parseObject(arrays.get(0).toString());
//                    // 获取不可见字符
//                    String invisibleName = this.invisibleService.getName();
//                    String command =  json.get("command").toString();
//                    json.put("command", StringEscapeUtils.unescapeJava(invisibleName) + "\n" +json.get("command"));
//                    arrays.clear();
//                    arrays.add(json);
//                    dto.setTasks(arrays);
//                    Object result = this.nodeUtil.postFormDataBody(dto, url, token);
//                    JSONObject resultJ = JSONObject.parseObject(result.toString());
//                    if(resultJ.get("status").toString().equals("0")) {
//                        // 更新字符状态
//                        Invisible invisible = new Invisible();
//                        invisible.setName(invisibleName);
//                        invisible.setStatus(1);
//                        this.invisibleService.update(invisible);
//                        // 执行完成 保存策略信息
//                        // 策略优化 查询策略信息
//                        if (dto.getFrom().equals("2")) {
//                            TopoPolicyDto policyDto = new TopoPolicyDto();
//                            policyDto.setCurrentPage(dto.getCurrentPage());
//                            policyDto.setPageSize(dto.getPageSize());
//                            policyDto.setDeviceUuid(dto.getDeviceUuid());
//                            policyDto.setType(dto.getType());
//                            String url2 = "/topology-policy/policy/check";
//                            Object policyResult = this.nodeUtil.postFormDataBody(policyDto, url2, token);
//                            JSONObject resultJson = JSONObject.parseObject(policyResult.toString());
//                            if (resultJson.get("data") != null) {
//                                JSONArray poliscyArrays = JSONArray.parseArray(resultJson.get("data").toString());
//                                if (poliscyArrays.size() > 0) {
//                                    for (Object array : poliscyArrays) {
//                                        JSONObject data = JSONObject.parseObject(array.toString());
//                                        if(data.get("index").toString().equals(dto.getIndex().toString())){
//                                            Policy policy = new Policy();
//                                            String random = CommUtils.randomString(6);
//                                            policy.setParentName(random);
//                                            policy.setDeviceUuid(dto.getDeviceUuid());
//                                            JSONArray details = JSONArray.parseArray(data.get("detailList").toString());
//                                            for (Object obj : details) {
//                                                Map map = JSON.parseObject(obj.toString(), Map.class);
//                                                map.put("parentName", random);
//                                                map.put("policyType", "RuleCheck_1");
//                                                map.put("deviceUuid", data.get("deviceUuid"));
//                                                map.put("invisible", invisibleName);
//                                                map.put("deviceName", data.get("deviceName"));
//                                                map.put("deviceType", data.get("deviceType"));
//                                                this.policyService.save(map);
//                                            }
//                                            // 更新策略信息，添加工单号
//                                            List<Policy> policysNew = this.policyService.getObjByMap(policy);
//                                            System.out.println(StringEscapeUtils.unescapeJava(invisibleName));
//                                            this.issuedService.queryTask(invisibleName, dto.getFrom(), policysNew, command);
//
//                                            break;
//                                        }
//                                    }
//                                }
//                            }
//
//                        }else if(dto.getFrom().equals("17")){ // 对象优化
//                            TopoPolicyDto policyDto = new TopoPolicyDto();
//                            policyDto.setCurrentPage(dto.getCurrentPage());
//                            policyDto.setPageSize(dto.getPageSize());
//                            policyDto.setDeviceUuid(dto.getDeviceUuid());
//                            policyDto.setType(dto.getType());
//                            policyDto.setObjectType(dto.getObjectType());
//                            String url2 = "/topology-policy/object/check";
//                            Object objectResult = this.nodeUtil.postFormDataBody(policyDto, url2, token);
//                            JSONObject objects = JSONObject.parseObject(objectResult.toString());
//                            if(objects.get("data") != null){
//                                JSONArray objectArray = JSONArray.parseArray(objects.get("data").toString());
//                                if(objectArray.size() > 0){
//                                    for(Object array : objectArray){
//                                        JSONObject data = JSONObject.parseObject(array.toString());
//                                        if(data.get("index").toString().equals(dto.getIndex().toString())){
//                                            // 执行批量删除
//                                            String random = CommUtils.randomString(6);
//                                            Policy policy = new Policy();
//                                            policy.setParentName(random);
//                                            policy.setDeviceUuid(dto.getDeviceUuid());
////                                          插入数据库
//                                            Map map = JSON.parseObject(data.toString(), Map.class);
//                                            map.put("policyType", "RC_EMPTY_OBJECT");
//                                            map.put("invisible", invisibleName);
//                                            map.put("parentName", random);
//                                            this.policyService.save(map);
//                                            // 更新策略信息，添加工单号
//                                            List<Policy> policysNew = this.policyService.getObjByMap(policy);
//                                            System.out.println(StringEscapeUtils.unescapeJava(invisibleName));
//                                            this.issuedService.queryTask(invisibleName, dto.getFrom(), policysNew, command);
//                                            break;
//                                        }
//
//                                    }
//                                }
//                            }
//
//                        }
//
//                    }
//                    return ResponseUtil.ok(result);
//                }
//            }
//            return ResponseUtil.badArgument();
//        }
//        return ResponseUtil.error();
//    }

    @RequestMapping("/delete")
    public Object delete(@RequestBody Policy policy){
        int i = this.policyService.delete(policy);
        return ResponseUtil.ok();
    }

    //
    @RequestMapping("/grade")
    public Object grade(@RequestBody TopoPolicyDto dto){
        // 计算总数
        // 策略统计
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        int total = 0;
        double score = 0;
        if(token != null){
            String url = "/topology-policy/report/policy/policy-list-pie";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            JSONObject policyResult = JSONObject.parseObject(result.toString());
            if(policyResult.get("data") != null){
                JSONObject data = JSONObject.parseObject(policyResult.get("data").toString());
                total += Integer.parseInt(data.get("total").toString());
            }
            // 对象统计
            String url2 = "/topology-policy/report/policy/object-list-pie";
            Object objectResult = this.nodeUtil.postFormDataBody(dto, url2, token);
            JSONObject ObjectResultJ = JSONObject.parseObject(objectResult.toString());
            if(ObjectResultJ.get("data") != null){
                JSONObject data = JSONObject.parseObject(ObjectResultJ.get("data").toString());
                total += Integer.parseInt(data.get("total").toString());
            }


            // 策略优化统计
            String url3 = "/topology-policy/report/policy/policy-check-pie";
            Object policyOptResult = this.nodeUtil.postFormDataBody(dto, url3, token);
            JSONObject policyOptResultJ = JSONObject.parseObject(policyOptResult.toString());
            if(policyOptResultJ.get("data") != null){
                JSONObject data = JSONObject.parseObject(policyOptResultJ.get("data").toString());
                JSONArray arrays = JSONArray.parseArray(data.get("statistics").toString());
                for(Object array : arrays){
                    JSONObject json = JSONObject.parseObject(array.toString());
                    // 根据测录Code查询对应策略
                    int value = Integer.parseInt(json.get("value").toString());
                    Double weight = this.policyStatisticalService.getObjByCode(json.get("code").toString());
                    BigDecimal b1 = new BigDecimal(value);

                    BigDecimal b2 = new BigDecimal(weight);
                    score += b1.multiply(b2).doubleValue();
                }
            }
            // 对象优化统计
            String url4 = "/topology-policy/report/policy/object-check-pie";
            Object objectOptResult = this.nodeUtil.postFormDataBody(dto, url4, token);
            JSONObject objectOptResultJ = JSONObject.parseObject(objectOptResult.toString());
            if(objectOptResultJ.get("data") != null){
                JSONObject data = JSONObject.parseObject(objectOptResultJ.get("data").toString());
                JSONArray arrays = JSONArray.parseArray(data.get("statistics").toString());
                for(Object array : arrays){
                    JSONObject json = JSONObject.parseObject(array.toString());
                    // 根据测录Code查询对应策略
                    int value = Integer.parseInt(json.get("value").toString());
                    double weight = this.policyStatisticalService.getObjByCode(json.get("name").toString());
                    BigDecimal b1 = new BigDecimal(value);
                    BigDecimal b2 = new BigDecimal(Double.toString(weight));
                    score += b1.multiply(b2).doubleValue();
                }
            }
        }
        BigDecimal b1 = new BigDecimal(Double.toString(total));

        BigDecimal b2 = new BigDecimal(score);

        Double b3 = b2.divide(b1, 2, RoundingMode.HALF_UP).doubleValue();

        BigDecimal b4 = new BigDecimal(1);

        return b4.subtract(new BigDecimal(b3)).doubleValue();

    }

}
