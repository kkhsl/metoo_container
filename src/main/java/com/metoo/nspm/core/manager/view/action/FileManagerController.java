package com.metoo.nspm.core.manager.view.action;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.entity.nspm.SysConfig;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URLEncoder;

@Controller
public class FileManagerController {

    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private NodeUtil nodeUtil;
    @Autowired
    private RestTemplate restTemplate;

    @RequestMapping(value = "upload")
    public String upload(HttpServletRequest request, HttpServletResponse response) throws UnsupportedEncodingException {

        String path = "C:\\Users\\46075\\Desktop\\metoo\\Logo\\soarmall.png";
        File file = new File(path);
        String fileName = file.getName();
        response.setHeader("Content-Disposition", "attachment;filename=" + URLEncoder.encode(fileName,"UTF-8"));
        try {
            InputStream inputStream = new FileInputStream(file);// 获取文件流
            int len = 0;
            byte[] buffer = new byte[1024];
            OutputStream out = response.getOutputStream();
            while((len = inputStream.read(buffer)) > 0){
                out.write(buffer,0, len);
            }
            out.close();
            inputStream.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "hello";
    }

    @ApiOperation("策略列表")
    @GetMapping(value = "uploadByte")
    public ResponseEntity uploadByte(HttpServletResponse response) throws IOException {
        SysConfig sysConfig = this.sysConfigService.select();
        String url = sysConfig.getNspmUrl();
        String token = sysConfig.getNspmToken();
        if(url != null && token != null){
            url = url + "/topology-policy/policy/rule-list-search";
            url = "https://39.104.167.48/topology/node/downloadHistory.action?id=230";
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + token);// 设置密钥
            HttpEntity<JSONObject> httpEntity = new HttpEntity<>(null, headers);

            ResponseEntity<byte[]> resEntity = restTemplate.exchange(url.toString(), HttpMethod.GET, httpEntity, byte[].class);
            return resEntity;
//            SystemTest.out.println(resEntity.getBody());
//            response.setHeader("Content-Disposition", "attachment;filename=" + URLEncoder.encode("test.conf","UTF-8"));
//            response.getOutputStream().write(resEntity.getBody());
        }
        return null;
    }

}
