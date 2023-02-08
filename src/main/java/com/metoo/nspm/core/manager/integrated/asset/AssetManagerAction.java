package com.metoo.nspm.core.manager.integrated.asset;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.AssetDto;
import com.metoo.nspm.dto.Risk;
import com.metoo.nspm.entity.nspm.SysConfig;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

//@RequiresPermissions("ADMIN:ASSET:MANAGER")
@Api("资产管理")
@RequestMapping("/nspm/asset")
@RestController
public class AssetManagerAction {

    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private NodeUtil nodeUtil;

    public static void main(String[] args) {
        String assetIpInfo = "电信内网:1.1.1.1[1.1.1.0/30][无逻辑安全域][CSZYW-ZTDC-2F1-A20-HLJR-HW-USG6680-005][澳大利亚],政企专线:2.2.2.2[186.0.0.0/30][无逻辑安全域][IDC_FW_212][法国]";

        String[] assetIpInfos = assetIpInfo.split(",");
        StringBuffer stringBuffer  = new StringBuffer();
        int i = 0;
        for(String asset : assetIpInfos){
            i ++;
            int indexOne = asset.indexOf("][",1);
            int indexTwo = asset.indexOf("][",asset.indexOf("][")+1);
            int indexThree = asset.indexOf("][",indexTwo+1);
            System.out.println(asset.substring(0,indexOne + 1));
            System.out.println(asset.substring(indexTwo + 1, indexThree + 1));
            asset = asset.substring(0,indexOne + 1)+ asset.substring(indexTwo + 1, indexThree + 1);
            if(i == assetIpInfos.length)
                stringBuffer.append(asset);
            else
                stringBuffer.append(asset).append(",");
        }
        System.out.println(stringBuffer);
    }

    @ApiOperation("主机组")
    @RequestMapping("/risk/api/danger/hostComputerSoftware/assetGroupTree")
    public Object assetGroupTree(@RequestBody AssetDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url =  "/risk/api/danger/hostComputerSoftware/assetGroupTree";
            Object object = this.nodeUtil.postBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("code").toString().equals("0")){
                return ResponseUtil.ok(result.get("data"));
            }
          return ResponseUtil.error(result.get("msg").toString());
        }
        return ResponseUtil.badArgument();
    }

    @ApiOperation("主机列表")
    @RequestMapping("/risk/api/danger/assetHost/pageTreeList")
    public Object pageTreeList(@RequestBody AssetDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/risk/api/danger/assetHost/pageTreeList";
            Object object = this.nodeUtil.postBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("code").toString().equals("0")){
                JSONObject data = JSONObject.parseObject(result.get("data").toString());
                JSONArray list = JSONArray.parseArray(data.get("list").toString());
                List MyList = new ArrayList();
                for (Object array : list){
                    JSONObject obj = JSONObject.parseObject(array.toString());
                    if(obj.get("assetIpInfo") != null && !obj.get("assetIpInfo").equals("")){
                        String assetIpInfo = obj.get("assetIpInfo").toString();
                        String[] assetIpInfos = assetIpInfo.split(",");
                        StringBuffer stringBuffer  = new StringBuffer();
                        int i = 0;
                        for(String asset : assetIpInfos){
                            i ++;
                            int indexOne = asset.indexOf("][",1);
                            int indexTwo = asset.indexOf("][",asset.indexOf("][")+1);
                            int indexThree = asset.indexOf("][",indexTwo+1);
                            System.out.println(asset.substring(0,indexOne + 1));
                            System.out.println(asset.substring(indexTwo + 1, indexThree + 1));
                            asset = asset.substring(0,indexOne + 1)+ asset.substring(indexTwo + 1, indexThree + 1);

                            if(i == assetIpInfos.length)
                                stringBuffer.append(asset);
                            else
                                stringBuffer.append(asset).append(",");
                        }
                        obj.put("assetIpInfo", stringBuffer);
                        MyList.add(obj);
                    }
                }
                data.put("list", MyList);
                return ResponseUtil.ok(data);
            }
            return ResponseUtil.error(result.get("msg").toString());
        }
        return ResponseUtil.badArgument();
    }

    @ApiOperation("包含服务")
    @RequestMapping("/risk/api/danger/hostComputerSoftware/hostComputerSoftwareListByAssetId")
    public Object hostComputerSoftwareListByAssetId(@RequestBody AssetDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url =  "/risk/api/danger/hostComputerSoftware/hostComputerSoftwareListByAssetId";
            Object object = this.nodeUtil.postFormDataBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("code").toString().equals("0")){
                return ResponseUtil.ok(result.get("data"));
            }
            return ResponseUtil.error(result.get("msg").toString());
        }
        return ResponseUtil.badArgument();
    }

    @ApiOperation("防火墙规则(iptables)")
    @RequestMapping("/risk/api/danger/assetHost/findIptablesByAssetUuid")
    public Object findIptablesByAssetUuid(@RequestBody AssetDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url =  "/risk/api/danger/assetHost/findIptablesByAssetUuid";
            Object object = this.nodeUtil.postFormDataBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("code").toString().equals("0")){
                return ResponseUtil.ok(result.get("data"));
            }
            return ResponseUtil.error(result.get("msg").toString());
        }
        return ResponseUtil.badArgument();
    }

    @ApiOperation("子网")
    @RequestMapping("/risk/api/danger/hostComputerSoftware/querySubnetUuidByIp")
    public Object querySubnetUuidByIp(@RequestBody AssetDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url =  "/risk/api/danger/hostComputerSoftware/querySubnetUuidByIp";
            Object object = this.nodeUtil.postFormDataBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("code").toString().equals("0")){
                return ResponseUtil.ok(result.get("data"));
            }
            return ResponseUtil.error(result.get("msg").toString());
        }
        return ResponseUtil.badArgument();
    }

    @ApiOperation("添加")
    @RequestMapping("/risk/api/danger/assetHost/addOrEdit")
    public Object addOrEdit(@RequestBody AssetDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url =  "/risk/api/danger/assetHost/addOrEdit";
            Object object = this.nodeUtil.postBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("code").toString().equals("0")){
                return ResponseUtil.ok(result.get("data"));
            }
            return ResponseUtil.error(result.get("msg").toString());
        }
        return ResponseUtil.badArgument();
    }

    @ApiOperation("编辑")
    @RequestMapping("/risk/api/danger/assetHost/getByAssetUuid")
    public Object getByAssetUuid(@RequestBody AssetDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url =  "/risk/api/danger/assetHost/getByAssetUuid";
            Object object = this.nodeUtil.postFormDataBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("code").toString().equals("0")){
                return ResponseUtil.ok(result.get("data"));
            }
            return ResponseUtil.error(result.get("msg").toString());
        }
        return ResponseUtil.badArgument();
    }

    @ApiOperation("批量修改主机分组")
    @RequestMapping("/risk/api/danger/hostComputerSoftware/updateAssetGroupByUUIds")
    public Object updateAssetGroupByUUIds(@RequestBody AssetDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url =  "/risk/api/danger/hostComputerSoftware/updateAssetGroupByUUIds";
            Object object = this.nodeUtil.postFormDataBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("code").toString().equals("0")){
                return ResponseUtil.ok(result.get("data"));
            }
            return ResponseUtil.error(result.get("msg").toString());
        }
        return ResponseUtil.badArgument();
    }

    @ApiOperation("主机厂商")
    @RequestMapping("/topology/assets/assetsOBJ_queryManufacturer.action")
    public Object assetsOBJ_queryManufacturer(@RequestBody AssetDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url =  "/topology/assets/assetsOBJ_queryManufacturer.action";
            Object object = this.nodeUtil.postFormDataBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("success").toString().equals("true")){
                return ResponseUtil.ok(result.get("data"));
            }
            return ResponseUtil.error(result.get("msg").toString());
        }
        return ResponseUtil.badArgument();
    }

    @ApiOperation("删除")
    @RequestMapping("/risk/api/danger/assetHost/batchDelete")
    public Object batchDelete(@RequestBody Risk dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url =  "/risk/api/danger/assetHost/batchDelete";
            Object object = this.nodeUtil.postBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("code").toString().equals("0")){
                return ResponseUtil.ok(result.get("data"));
            }
            return ResponseUtil.error(result.get("msg").toString());
        }
        return ResponseUtil.badArgument();
    }

    @ApiOperation("主机组列表")
    @RequestMapping("/risk/api/danger/hostComputerSoftware/assetGroupList")
    public Object assetGroupList(@RequestBody AssetDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
        String url =  "/risk/api/danger/hostComputerSoftware/assetGroupList";
            Object object = this.nodeUtil.postBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("code").toString().equals("0")){
                return ResponseUtil.ok(result.get("data"));
            }
            return ResponseUtil.error(result.get("msg").toString());
        }
        return ResponseUtil.badArgument();
    }

    @ApiOperation("主机组编辑")
    @RequestMapping("/risk/api/danger/hostComputerSoftware/editAssetGroup")
    public Object editAssetGroup(@RequestBody AssetDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/risk/api/danger/hostComputerSoftware/editAssetGroup";
            Object object = this.nodeUtil.postBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("code").toString().equals("0")){
                return ResponseUtil.ok(result.get("data"));
            }
            return ResponseUtil.error(result.get("msg").toString());
        }
        return ResponseUtil.badArgument();
    }

    @ApiOperation("主机组删除")
    @RequestMapping("/risk/api/danger/hostComputerSoftware/deleteAssetGroupByArrayIds")
    public Object deleteAssetGroupByArrayIds(@RequestBody AssetDto dto){
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url =  "/risk/api/danger/hostComputerSoftware/deleteAssetGroupByArrayIds";
            Object object = this.nodeUtil.postBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("code").toString().equals("0")){
                return ResponseUtil.ok(result.get("data"));
            }
            return ResponseUtil.error(result.get("msg").toString());
        }
        return ResponseUtil.badArgument();
    }
}
