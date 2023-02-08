package com.metoo.nspm.core.manager.integrated.node;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.core.utils.collections.ListSortUtil;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.TopoNodeDto;
import com.metoo.nspm.dto.TopoPolicyDto;
import com.metoo.nspm.entity.nspm.SysConfig;
import com.metoo.nspm.entity.nspm.Task;
import com.metoo.nspm.entity.nspm.User;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigDecimal;
import java.util.*;

@Api("系统首页")
@RequestMapping("/nspm/index")
@RestController
public class TopoNspmIndexManagerAction {

    @Autowired
    private IssuedService issuedService;
    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private static ListSortUtil listSortUtil;
    @Autowired
    private IUserService userService;
    @Autowired
    private NodeUtil nodeUtil;
    @Autowired
    private IPolicyService policyService;
    @Autowired
    private IPolicyStatisticalService policyStatisticalService;

    public static void main(String[] args) {
        List<Map<String, Integer>> list = new ArrayList<Map<String, Integer>>();
        Map map1 = new HashMap();
        Map map2 = new HashMap();
        Map map3 = new HashMap();
        map1.put("policyCheckTotal",91);
        map2.put("policyCheckTotal", 50);
        map3.put("policyCheckTotal",100);
        list.add(map1);
        list.add(map2);
        list.add(map3);
//        listSortUtil.sort(list);
        System.out.println(list);


    }

    @RequestMapping("/task")
    public Object task(){
        List<Task> tasks = this.issuedService.query();
        return ResponseUtil.ok(tasks);
    }


    @RequestMapping("/policy")
    public Object policy(){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String policyUrl = "/topology-policy/report/policyView/viewData";
            TopoPolicyDto policyDto = new TopoPolicyDto();
            policyDto.setCurrentPage(1);
            policyDto.setPageSize(100000);
            User currentUser = ShiroUserHolder.currentUser();
            User user = this.userService.findByUserName(currentUser.getUsername());
            policyDto.setBranchLevel(user.getGroupLevel());
            Object policy = this.nodeUtil.postFormDataBody(policyDto, policyUrl, token);
            JSONObject json = JSONObject.parseObject(policy.toString());
            if(json.get("data") != null){
                List<Map<String, Double>> list = new ArrayList<Map<String, Double>>();
                JSONArray datas = JSONArray.parseArray(json.get("data").toString());
                for(Object object : datas){
                    Map dataMap = new HashMap();
                    dataMap.put("grade", new Double(100));
                    dataMap.put("objectTotal", 0);
                    dataMap.put("policyTotal", 0);
                    dataMap.put("policyCheckTotal", 0);
                    dataMap.put("objectCheckTotal", 0);
                    JSONObject data = JSONObject.parseObject(object.toString());
                    dataMap.put("deviceName", data.get("deviceName"));
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
                    }
                    dataMap.put("policyTotal", policyTotal);
                    // 对象总数
                    Integer objectTotal = data.get("objectTotal") != null ? Integer.parseInt(data.get("objectTotal").toString()) : 0;
                    dataMap.put("objectTotal", objectTotal);
                    Integer total  = policyTotal + objectTotal;
                    if(total > 0){
                        // 问题策略数
                        dataMap.put("policyCheckTotal", data.get("policyCheckTotal") != null ? data.get("policyCheckTotal") : 0);
                        // 问题对象数
                        dataMap.put("objectCheckTotal", data.get("objectCheckTotal") != null ? data.get("objectCheckTotal") : 0);
                        // 健康度
                        // 计算问题策略权重
                        double policyGrade = 0;
                        if(data.get("policyCheckTotalDetail") != null){
                            JSONArray detail = JSONArray.parseArray(data.get("policyCheckTotalDetail").toString());
                            if(detail.size() > 0){
                                Map<String, Integer> map = JSONObject.parseObject(detail.get(0).toString(), Map.class);
                                Set<String> keys = map.keySet();
                                Iterator<String> it = keys.iterator();
                                while (it.hasNext()){
                                    String key =  it.next();
                                    // 获取策略权重
                                    double weight = this.policyStatisticalService.getObjByCode(key);
                                    Integer value = map.get(key);
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
                                Map<String, Integer> map = JSONObject.parseObject(detail.get(0).toString(), Map.class);
                                Set<String> keys = map.keySet();
                                Iterator<String> it = keys.iterator();
                                while (it.hasNext()){
                                    String key =  it.next();
                                    // 获取对象权重
                                    double weight = this.policyStatisticalService.getObjByCode(key);
                                    Integer value = map.get(key);
                                    BigDecimal b1 = new BigDecimal(value);
                                    BigDecimal b2 = new BigDecimal(weight);
                                    objectGrade += b1.multiply(b2).doubleValue();
                                }
                            }
                        }
                        double checkTotal = policyGrade + objectGrade;
                        BigDecimal b1 = new BigDecimal(Double.toString(total));
                        BigDecimal b2 = new BigDecimal(Double.toString(checkTotal));
                        BigDecimal b3 = b2.divide(b1, 2, BigDecimal.ROUND_HALF_UP);
                        BigDecimal b4 = new BigDecimal(1);
                        Double grade = 0.0;
                        if(b3.compareTo(b4) > 0) {
                            grade = 0.0;
                        }else{
                            BigDecimal grade1 = b4.subtract(b3);
                            double a = Math.round(grade1.doubleValue());
                            dataMap.put("grade", a);
                        }
                    }else{
                        dataMap.put("grade", new Double(100));
                    }

                    list.add(dataMap);
                }
                // 排序
                listSortUtil.sort(list);
                List list1 = list.subList(0,list.size() < 10 ? list.size() : 10);
                return ResponseUtil.ok(list1);
            }
        }
        return ResponseUtil.ok();
    }

    @RequestMapping(value="/devices")
    public Object devices(@RequestBody(required = false) TopoNodeDto dto){
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/node/getChangeDevices.action";
            Object result = this.nodeUtil.postBody(dto, url, token);
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
            JSONObject resultJ = JSONObject.parseObject(result.toString());
            if(resultJ.get("data") != null){
                JSONObject data = JSONObject.parseObject(resultJ.get("data").toString());
                JSONArray arrays = JSONArray.parseArray(data.get("statistics").toString());
                if(arrays.size() > 0){
                    for(Object object : arrays){
                        JSONObject policy = JSONObject.parseObject(object.toString());
                        if(policy.get("name").toString().equals("域外策略")){
                            arrays.remove(policy);
                        }
                    }
                    data.put("statistics",arrays);
                    resultJ.put("data",data);
                }
            }
            return ResponseUtil.ok(resultJ);
        }
        return ResponseUtil.error();
    }


}
