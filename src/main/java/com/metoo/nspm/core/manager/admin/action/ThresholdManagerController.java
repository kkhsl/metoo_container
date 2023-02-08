package com.metoo.nspm.core.manager.admin.action;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.service.api.zabbix.IUserMacroService;
import com.metoo.nspm.core.service.nspm.IThresholdService;
import com.metoo.nspm.core.utils.BasicDate.BasicDataConvertUtil;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.ThresholdDTO;
import com.metoo.nspm.dto.zabbix.UserMacroDTO;
import com.metoo.nspm.entity.nspm.Threshold;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.junit.Test;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

@Api("宏")
@RequestMapping("/admin/threshold")
@RestController
public class ThresholdManagerController {

    @Autowired
    private IThresholdService thresholdService;
    @Autowired
    private IUserMacroService userMacroService;

    public static void main(String[] args) {
        double i = 0.5;
        Double cpu = i / 100;
        System.out.println(BasicDataConvertUtil.bigDecimalSetScale(cpu));


        BigDecimal num1 = new BigDecimal(0.04);
        BigDecimal num2 = new BigDecimal("100");
        BigDecimal num3 = new BigDecimal("0");

        int compare1 = num1.compareTo(num2);
        int compare2 = num1.compareTo(num3);
        System.out.println(compare1);
        System.out.println(compare2);
    }

    @ApiOperation("zabbix 全局阈值")
    @GetMapping("/list")
    public Object get(){
//        this.thresholdService.query();// 自定义宏（全局阈值）
        UserMacroDTO dto = new UserMacroDTO();
        dto.setGlobalmacro(true);
        JSONArray jsonArray = this.userMacroService.getUserMacros(dto);
        List list = new ArrayList();
        for (int i = 0; i < jsonArray.size(); i++) {
            Threshold threshold  = new Threshold();
            JSONObject jsonObject = jsonArray.getJSONObject(i);
            String macro = jsonObject.getString("macro");
            switch (macro){
                case "{$CPU_THRESHLD}" :
                    BigDecimal a = new BigDecimal(100);
                    BigDecimal b = new BigDecimal(jsonObject.getString("value"));
                    BigDecimal c = a.multiply(b);
                    threshold.setCpu(c.stripTrailingZeros().toPlainString());
                    threshold.setGlobalmacroid(jsonObject.getString("globalmacroid"));
                    threshold.setType(1);
                    list.add(threshold);
                    break;
                case "{$MEM_THRESHLD}":
                    BigDecimal aa = new BigDecimal(100);
                    BigDecimal d = new BigDecimal(jsonObject.getString("value"));
                    BigDecimal f = d.multiply(aa);
                    threshold.setMemory(f.stripTrailingZeros().toPlainString());
                    threshold.setGlobalmacroid(jsonObject.getString("globalmacroid"));
                    threshold.setType(2);
                    list.add(threshold);
                    break;
                case "{$TRAFFIC_THRESHLD}":

                    BigDecimal aaa = new BigDecimal(100);
                    BigDecimal e = new BigDecimal(jsonObject.getString("value"));
                    BigDecimal ff = e.multiply(aaa);
                    threshold.setFlow(ff.stripTrailingZeros().toPlainString());
                    threshold.setGlobalmacroid(jsonObject.getString("globalmacroid"));
                    threshold.setType(3);
                    list.add(threshold);
                    break;
                default:
                    break;
            }
        }
        return ResponseUtil.ok(list);
    }

    @ApiOperation("zabbix阈值更新")
    @PutMapping("/update")
    public Object update(@RequestBody List<UserMacroDTO> dtos){
        if(dtos.size() > 0){
            List list = new ArrayList();
            for (UserMacroDTO dto : dtos) {
                BigDecimal num1 = new BigDecimal(dto.getValue());
                BigDecimal num2 = new BigDecimal("100");
                BigDecimal num3 = new BigDecimal("0");
                int compare1 = num1.compareTo(num2);
                int compare2 = num1.compareTo(num3);
                if (compare1 == 1 || compare2 == -1) {
                    return ResponseUtil.badArgument("阈值不符合规范");
                }
            }
            for (UserMacroDTO dto : dtos) {
                if(dto.getValue() != null && !dto.getValue().equals("")){
                    BigDecimal num1 = new BigDecimal(dto.getValue());
                    BigDecimal num2= new BigDecimal("100");
                    BigDecimal  v = num1.divide(num2);
                    dto.setValue(v.toPlainString());
                }
                JSONObject result =  this.userMacroService.updateUserMacros(dto);
                if(result.getString("globalmacroids") != null){
                    list.addAll(result.getJSONArray("globalmacroids"));
                }else{
                    return ResponseUtil.error(result.get("data").toString());
                }
            }
            if(list.size() > 0){
                return ResponseUtil.ok(list);
            }else{
                return ResponseUtil.error();
            }
        }
        return ResponseUtil.badArgument();
    }

//    @ApiOperation("自定义阈值更新")
//    @PutMapping("/update")
//    public Object update(@RequestBody ThresholdDTO dto){
//        if(dto.getCpu() < 0 || dto.getFlow() < 0 || dto.getMemory() < 0){
//            return ResponseUtil.badArgument();
//        }
//        Threshold threshold = new Threshold();
//        BeanUtils.copyProperties(dto, threshold);
//        int result = this.thresholdService.update(threshold);
//        return result >= 1 ? ResponseUtil.ok() : ResponseUtil.error();
//    }

}
