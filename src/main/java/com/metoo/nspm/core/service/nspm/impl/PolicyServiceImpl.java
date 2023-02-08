package com.metoo.nspm.core.service.nspm.impl;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.mapper.nspm.PolicyMapper;
import com.metoo.nspm.core.service.nspm.IPolicyService;
import com.metoo.nspm.core.service.nspm.IPolicyStatisticalService;
import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.core.service.nspm.IUserService;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.dto.TopoPolicyDto;
import com.metoo.nspm.entity.nspm.Policy;
import com.metoo.nspm.entity.nspm.SysConfig;
import com.metoo.nspm.entity.nspm.User;
import com.github.pagehelper.util.StringUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.*;

@Service
public class PolicyServiceImpl implements IPolicyService {

    @Autowired
    private PolicyMapper policyMapper;
    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private NodeUtil nodeUtil;
    @Autowired
    private IPolicyStatisticalService policyStatisticalService;
    @Autowired
    private IUserService userService;

    @Override
    public Policy getObjById(String id) {
        return this.policyMapper.getObjById(id);
    }

    @Override
    public List<Policy> getObjByParentId(String parentId) {
        return this.policyMapper.getObjByParentId(parentId);
    }

    @Override
    public List<Policy> getObjOrderNo(String orderNo) {
        return this.policyMapper.getObjOrderNo(orderNo);
    }

    @Override
    public List<Policy> getObjByMap(Policy instance) {
        return this.policyMapper.getObjByMap(instance);
    }


    @Override
    public int save(Map policy) {
        return this.policyMapper.save(policy);
    }

    @Override
    public int delete(Policy policy) {
        return this.policyMapper.delete(policy);
    }

    @Override
    public Double getGrade(String deviceUuid) {
        if(deviceUuid != null && !deviceUuid.equals("")){
            TopoPolicyDto dto = new TopoPolicyDto();
            dto.setDeviceUuid(deviceUuid);
            // 计算总数
            // 策略统计
            SysConfig sysConfig = this.sysConfigService.select();
            String token = sysConfig.getNspmToken();
            int total = 0;
            double score = 0;
            if(token != null){
                String policyUrl = "/topology-policy/report/policy/policy-list-pie";
                Object result = this.nodeUtil.postFormDataBody(dto, policyUrl, token);
                JSONObject policyResult = JSONObject.parseObject(result.toString());
                if(policyResult.get("data") != null){
                    JSONObject data = JSONObject.parseObject(policyResult.get("data").toString());
                    total += Integer.parseInt(data.get("total").toString());
                }
                // 对象统计
                String objectUrl = "/topology-policy/report/policy/object-list-pie";
                Object objectResult = this.nodeUtil.postFormDataBody(dto, objectUrl, token);
                JSONObject ObjectResultJ = JSONObject.parseObject(objectResult.toString());
                if(ObjectResultJ.get("data") != null){
                    JSONObject data = JSONObject.parseObject(ObjectResultJ.get("data").toString());
                    total += Integer.parseInt(data.get("total").toString());
                }

                if(total != 0){
                    // 问题策略优化统计
                    String policyOptUrl =  "/topology-policy/report/policy/policy-check-pie";
                    Object policyOptResult = this.nodeUtil.postFormDataBody(dto, policyOptUrl, token);
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
                    // 问题对象优化统计
                    String objectOptUrl = "/topology-policy/report/policy/object-check-pie";
                    Object objectOptResult = this.nodeUtil.postFormDataBody(dto, objectOptUrl, token);
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

                score = score == 0 ? 1 : score;
                BigDecimal b2 = new BigDecimal(score);
                Double b3 = b2.divide(b1, 2, RoundingMode.HALF_UP).doubleValue();

                BigDecimal b4 = new BigDecimal(1);
                return b4.subtract(new BigDecimal(Double.toString(b3))).doubleValue() * 100;
            }
               return new Double(99);
        }
        return null;
    }

    @Override
    public int update(List<Policy> policies) {
        return this.policyMapper.update(policies);
    }

    @Override
    public Double HealthScore(String deviceUuid) {
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if (token != null && !StringUtil.isEmpty(deviceUuid)) {
            String policyUrl = "/topology-policy/report/policyView/viewData";
            TopoPolicyDto policyDto = new TopoPolicyDto();
            policyDto.setCurrentPage(1);
            policyDto.setPageSize(100000);
            policyDto.setDeviceUuid(deviceUuid);
            User currentUser = ShiroUserHolder.currentUser();
            User user = this.userService.findByUserName(currentUser.getUsername());
            policyDto.setBranchLevel(user.getGroupLevel());
            Object policy = this.nodeUtil.postFormDataBody(policyDto, policyUrl, token);
            JSONObject json = JSONObject.parseObject(policy.toString());
            if (json.get("data") != null) {
                List<Map<String, Double>> list = new ArrayList<Map<String, Double>>();
                JSONArray datas = JSONArray.parseArray(json.get("data").toString());
               if(datas.size() > 0){
                   for (Object object : datas) {
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
                       if (data.get("policyTotalDetail") != null) {
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
                       Integer total = policyTotal + objectTotal;
                       if (total > 0) {
                           // 问题策略数
                           dataMap.put("policyCheckTotal", data.get("policyCheckTotal") != null ? data.get("policyCheckTotal") : 0);
                           // 问题对象数
                           dataMap.put("objectCheckTotal", data.get("objectCheckTotal") != null ? data.get("objectCheckTotal") : 0);
                           // 健康度
                           // 计算问题策略权重
                           double policyGrade = 0;
                           if (data.get("policyCheckTotalDetail") != null) {
                               JSONArray detail = JSONArray.parseArray(data.get("policyCheckTotalDetail").toString());
                               if (detail.size() > 0) {
                                   Map<String, Integer> map = JSONObject.parseObject(detail.get(0).toString(), Map.class);
                                   Set<String> keys = map.keySet();
                                   Iterator<String> it = keys.iterator();
                                   while (it.hasNext()) {
                                       String key = it.next();
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
                           if (data.get("objectCheckTotalDetail") != null) {
                               JSONArray detail = JSONArray.parseArray(data.get("objectCheckTotalDetail").toString());
                               if (detail.size() > 0) {
                                   Map<String, Integer> map = JSONObject.parseObject(detail.get(0).toString(), Map.class);
                                   Set<String> keys = map.keySet();
                                   Iterator<String> it = keys.iterator();
                                   while (it.hasNext()) {
                                       String key = it.next();
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
                           if (b3.compareTo(b4) > 0) {
                               dataMap.put("grade", new Double(0));
                               return new Double(0);
                           }else{
                               return b4.subtract(b3).doubleValue() * 100;}
                       }

                   }
               }
            }
        }
        return new Double(100);
    }
}
