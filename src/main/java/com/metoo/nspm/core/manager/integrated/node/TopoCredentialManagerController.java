package com.metoo.nspm.core.manager.integrated.node;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.service.nspm.IGroupService;
import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.core.service.nspm.IUserService;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.TopoCredentialDto;
import com.metoo.nspm.entity.nspm.Group;
import com.metoo.nspm.entity.nspm.SysConfig;
import com.metoo.nspm.entity.nspm.User;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

//@RequiresPermissions("ADMIN:CREDENTIAL:MANAGER")
@Api("凭据")
@RequestMapping({"/nspm/credential"})
@RestController
public class TopoCredentialManagerController {
    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private NodeUtil nodeUtil;
    @Autowired
    private IUserService userService;
    @Autowired
    private IGroupService groupService;

    public static void main(String[] args) {
        String key = "0-65535";
        System.out.println(key.substring(0,key.indexOf("-")));
        System.out.println(key.length());
        System.out.println(key.indexOf("-"));
        System.out.println(key.length() - key.indexOf("-"));
        System.out.println(key.substring(key.indexOf("-")));

    }

    public TopoCredentialManagerController() {
    }

    @ApiOperation("列表")
    @RequestMapping({"/push/credential/getall"})
    public Object getall(@RequestBody(required = false) TopoCredentialDto dto) {
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            if (dto.getBranchLevel() == null || dto.getBranchLevel().equals("")) {
                User currentUser = ShiroUserHolder.currentUser();
                User user = this.userService.findByUserName(currentUser.getUsername());
                dto.setBranchLevel(user.getGroupLevel());
            }
            String url = "/push/credential/getall";
            Object object = this.nodeUtil.postBody(dto, url, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if (result.get("content") != null) {
                JSONObject content = JSONObject.parseObject(result.get("content").toString());
                if (content.get("list") != null) {
                    List list = new ArrayList();
                    JSONArray arrays = JSONArray.parseArray(content.get("list").toString());
                    JSONObject json;
                    for(Iterator var10 = arrays.iterator(); var10.hasNext(); list.add(json)) {
                        Object array = var10.next();
                        json = JSONObject.parseObject(array.toString());
                        if (json.get("branchLevel") != null) {
                            Group group = this.groupService.getObjByLevel(json.get("branchLevel").toString());
                            if (group != null) {
                                json.put("branchName", group.getBranchName());
                            } else {
                                json.put("branchName", "");
                            }
                        }
                    }
                    result.put("list", list);
                }
            }

            return ResponseUtil.ok(object);
        } else {
            return ResponseUtil.error();
        }
    }

    @ApiOperation("新增")
    @RequestMapping({"/push/credential/create"})
    public Object create(@RequestBody(required = false) TopoCredentialDto dto) {
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String createUrl = "/push/credential/create";
            Object object = this.nodeUtil.postBody(dto, createUrl, token);
            JSONObject result = JSONObject.parseObject(object.toString());
            if(result.get("code").toString().equals("200")){
              // 查询uuid
                TopoCredentialDto dto1 = new TopoCredentialDto();
                dto.setBranchLevel("");
                dto.setPageIndex(1);
                dto.setPageSize(10);
                dto.setSelectBox("false");
                String getUrl = "/push/credential/getall";
                Object credential = this.nodeUtil.postBody(dto, getUrl, token);
                JSONObject credentialJson = JSONObject.parseObject(credential.toString());
                if (credentialJson.get("content") != null) {
                    JSONObject content = JSONObject.parseObject(credentialJson.get("content").toString());
                    if (content.get("list") != null) {
                        JSONArray arrays = JSONArray.parseArray(content.get("list").toString());
                        for(Iterator var10 = arrays.iterator(); var10.hasNext();) {
                            Object array = var10.next();
                            JSONObject json = JSONObject.parseObject(array.toString());
                            String uuid = json.get("uuid").toString();
                            // 分配组
                            TopoCredentialDto dto2 = new TopoCredentialDto();
                            User currentUser = ShiroUserHolder.currentUser();
                            User user = this.userService.findByUserName(currentUser.getUsername());
                            dto2.setBranchLevel(user.getGroupLevel());
                            dto2.setUuid(uuid);
                            String updateurl = "/push/credential/batch-credential-update";
                            this.nodeUtil.postBody(dto2, updateurl, token);
                            break;
                        }
                    }
                }
            }
            return ResponseUtil.ok(result);
        } else {
            return ResponseUtil.error();
        }
    }

    @ApiOperation("编辑")
    @RequestMapping({"/push/credential/get"})
    public Object get(@RequestBody(required = false) TopoCredentialDto dto) {
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/credential/get";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        } else {
            return ResponseUtil.error();
        }
    }

    @ApiOperation("编辑保存")
    @RequestMapping({"/push/credential/modify"})
    public Object modify(@RequestBody(required = false) TopoCredentialDto dto) {
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/credential/modify";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        } else {
            return ResponseUtil.error();
        }
    }

    @ApiOperation("删除")
    @RequestMapping({"/push/credential/delete"})
    public Object delete(@RequestBody(required = false) TopoCredentialDto dto) {
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/credential/delete";
            Object result = this.nodeUtil.postFormDataBody(dto, url, token);
            return ResponseUtil.ok(result);
        } else {
            return ResponseUtil.error();
        }
    }

    @ApiOperation("分配组")
    @RequestMapping({"/push/credential/batch-credential-update"})
    public Object batch_credential_update(@RequestBody(required = false) TopoCredentialDto dto) {
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/credential/batch-credential-update";
            Object result = this.nodeUtil.postBody(dto, url, token);
            return ResponseUtil.ok(result);
        } else {
            return ResponseUtil.error();
        }
    }

    @ApiOperation("导出")
    @GetMapping({"/push/credential/export-credential"})
    public Object export_credential(HttpServletResponse response, TopoCredentialDto dto) {
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/credential/export-credential";
            if (dto.getIsReload() != null || dto.getIsTrusted() != null) {
                if (dto.getIsReload() != null && !dto.getIsReload()) {
                    Map map = new HashMap();
                    map.put("isReload", dto.getIsReload());
                    return this.nodeUtil.download(map, url, token);
                }

                Object result = this.nodeUtil.getBody(dto, url, token);
                return ResponseUtil.ok(result);
            }
        }

        return ResponseUtil.error();
    }

    @ApiOperation("下载模板")
    @RequestMapping({"/push/credential/download-credential-template"})
    public Object download_credential_template() {
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/credential/download-credential-templates";
            Object result = this.nodeUtil.postBody((Object)null, url, token);
            return ResponseUtil.ok(result);
        } else {
            return ResponseUtil.error();
        }
    }

    @ApiOperation("导出")
    @GetMapping({"/push/downloadFile/template"})
    public Object template(HttpServletResponse response, TopoCredentialDto dto) {
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/downloadFile/凭据批量生成模板.xls";
            return this.nodeUtil.download((Map)null, url, token);
        } else {
            return ResponseUtil.error();
        }
    }

    @ApiOperation("导入文件")
    @RequestMapping({"/push/credential/import-credential"})
    public Object upload(@RequestParam(value = "multipartFile",required = false) MultipartFile file, String encrypt) throws IOException {
        SysConfig sysConfig = this.sysConfigService.select();
        
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/credential/import-credential";
            ByteArrayResource fileAsResource = new ByteArrayResource(file.getBytes()) {
                public String getFilename() {
                    return file.getOriginalFilename();
                }

                public long contentLength() {
                    return file.getSize();
                }
            };
            MultiValueMap<String, Object> multipartRequest = new LinkedMultiValueMap();
            multipartRequest.add("file", fileAsResource);
            multipartRequest.add("fileName", file.getName());
            multipartRequest.add("fileSize", file.getSize());
            multipartRequest.add("encrypt", encrypt);
            Object result = this.nodeUtil.post_form_data(multipartRequest, url, token);
            return ResponseUtil.ok(result);
        } else {
            return ResponseUtil.error();
        }
    }
}

