package com.metoo.nspm.core.manager.integrated.dbbackup;

import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.httpclient.UrlConvertUtil;
import com.metoo.nspm.entity.nspm.BackUp;
import com.metoo.nspm.entity.nspm.BackupFtp;
import com.metoo.nspm.entity.nspm.SysConfig;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Api("数据库维护")
@RequestMapping("/nspm/db")
@RestController
public class BackupController {

    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private NodeUtil nodeUtil;
    @Autowired
    private UrlConvertUtil urlConvertUtil;
    @Autowired
    private RestTemplate restTemplate;

    @ApiOperation("ftp设置")
    @RequestMapping("/getBackupFtpList")
    public Object getBackupFtpList(@RequestBody(required = false) BackupFtp backupFtp){
            SysConfig sysConfig = this.sysConfigService.select();

            String token = sysConfig.getNspmToken();
            if(token != null){
                String url = "/topology/db/getBackupFtpList.action";
                Object result = this.nodeUtil.postBody(backupFtp, url, token);
                return ResponseUtil.ok(result);
            } else {
                return ResponseUtil.error();
            }
        }

    @ApiOperation("数据库安装模式信息")
    @RequestMapping("/getMasterOrSlave")
    public Object getMasterOrSlave(){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/db/getMasterOrSlave.action";
            Object result = this.nodeUtil.postBody(null, url, token);
            return ResponseUtil.ok(result);
        } else {
            return ResponseUtil.error();
        }
    }

    @ApiOperation("备份结果查看/系统还原")
    @GetMapping("/querybackupdata")
    public Object getMasterOrSlave(BackUp backUp){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/db/querybackupdata.action";
            Object result = this.nodeUtil.getBody(backUp, url, token);
            return ResponseUtil.ok(result);
        } else {
            return ResponseUtil.error();
        }
    }

    @ApiOperation("备份方式")
    @RequestMapping("/querybackupconfig")
    public Object querybackupconfig(@RequestBody(required = false)BackUp backUp){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/db/querybackupconfig.action";
            Object result = this.nodeUtil.getBody(backUp, url, token);
            return ResponseUtil.ok(result);
        } else {
            return ResponseUtil.error();
        }
    }

    @ApiOperation("系统工作目录剩余空间")
    @RequestMapping("/getFreeDiskSize")
    public Object getFreeDiskSize(@RequestBody(required = false)BackUp backUp){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/db/getFreeDiskSize.action";
            Object result = this.nodeUtil.getBody(null, url, token);
            return ResponseUtil.ok(result);
        } else {
            return ResponseUtil.error();
        }
    }

    @ApiOperation("保存期限设置")
    @RequestMapping("/addBackupConfig")
    public Object addBackupConfig(@RequestBody(required = false)BackUp backUp){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/db/addBackupConfig.action";
            Object result = this.nodeUtil.getBody(backUp, url, token);
            return ResponseUtil.ok(result);
        } else {
            return ResponseUtil.error();
        }
    }

    @ApiOperation("删除")
    @RequestMapping("/deletebackupdata")
    public Object deletebackupdata(@RequestBody BackUp backUp){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/db/deletebackupdata.action";
            Object result = this.nodeUtil.getBody(backUp, url, token);
            return ResponseUtil.ok(result);
        } else {
            return ResponseUtil.error();
        }
    }

    @ApiOperation("上传")
    @PostMapping(value = "/upload")
    public Object upload(@RequestParam(value = "file", required = false) MultipartFile file, String fileName, Integer fileSize) throws IOException {
        SysConfig sysConfig = this.sysConfigService.select();

        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/topology/db/uploadBackupDate.action";
            url = this.urlConvertUtil.convert(url);
            if(!file.isEmpty()){
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
                multValueMap.add("fileName", fileName);
                multValueMap.add("fileSize", fileSize);
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.MULTIPART_FORM_DATA);
                headers.set("Authorization", "Bearer " + token);// 设置密钥
                HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity(multValueMap, headers);
                //发起调用
                Object obj =  restTemplate.postForObject(url, requestEntity, Object.class);
                return ResponseUtil.ok(obj);
            }
            return ResponseUtil.badArgument();
        }
        return ResponseUtil.error();
    }

    @ApiOperation("下载")
    @GetMapping(value="/downloadBackupDate")
    public Object downloadBackupDate(@RequestParam("filePath") String filePath){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url =  "/topology/db/downloadBackupDate.action";
            Map map = new HashMap();
            map.put("filePath", filePath);
            return this.nodeUtil.download(map, url, token);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("备份")
    @GetMapping(value="/backup")
    public Object backup(BackUp backUp){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url =  "/topology/db/backup.action";
            Object result = this.nodeUtil.getBody(backUp, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("还原")
    @GetMapping(value="/dbRestore")
    public Object downloadBackupDate(BackUp backUp){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url =  "/topology/db/dbRestore.action";
            Object result = this.nodeUtil.getBody(backUp, url, token);
            return ResponseUtil.ok(result) ;
        }
        return ResponseUtil.error();
    }

    @ApiOperation("还原状态")
    @PostMapping(value="/getBackupOrRecoverStatusData")
    public Object getBackupOrRecoverStatusData(){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url =  "/topology/db/getBackupOrRecoverStatusData.action";
            Object result = this.nodeUtil.postBody(null, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("重置")
    @PostMapping(value="/resetStatus.action")
    public Object resetStatus(){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url =  "/topology/db/resetStatus.action";
            Object result = this.nodeUtil.postBody(null, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }

    @ApiOperation("FTP设置-保存")
    @PostMapping(value="/saveOrUpdateBackupFtp.action")
    public Object saveOrUpdateBackupFtp(@RequestBody(required = false) BackUp backUp){
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url =  "/topology/db/saveOrUpdateBackupFtp.action";
            Object result = this.nodeUtil.postFormDataBody(backUp, url, token);
            return ResponseUtil.ok(result);
        }
        return ResponseUtil.error();
    }
}
