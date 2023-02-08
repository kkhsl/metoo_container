package com.metoo.nspm.core.manager.integrated.utils;

import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.core.utils.httpclient.UrlConvertUtil;
import com.metoo.nspm.entity.nspm.SysConfig;

import java.io.*;
import java.util.Base64;

import org.apache.commons.beanutils.BeanMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Component
public class RestTemplateUtil {

    @Autowired
    private NodeUtil nodeUtil;
    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private RestTemplate restTemplate;


    @Autowired
    private UrlConvertUtil urlConvertUtil;

    public String parseUrl(String url){
        return this.urlConvertUtil.convert(url);
    }

    public String getToken(){
        SysConfig sysConfig = this.sysConfigService.select();
        return sysConfig.getNspmToken();

    }

    public String remoteJsonRequest(String url, Object object){
        url = this.parseUrl(url);
        String token = this.getToken();
        Map<String, Object> map = new BeanMap(object);
        return null;
    }


    // 获取文件流
   /* public String getInputStream(String url){
        // 通过url获取输入流
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(url != null && token != null){
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + token);// 设置密钥
            headers.setContentType(MediaType.MULTIPART_FORM_DATA);

            HttpEntity httpEntity = new HttpEntity(headers);
            ResponseEntity<Resource> response  = restTemplate.exchange(url, HttpMethod.GET, httpEntity, Resource.class);
            InputStream in = null;
            byte[] data = null;
            try {
                in = response.getBody().getInputStream();
                data = new byte[in.available()];
                in.read(data);
                in.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            return new String(Base64.getEncoder().encode(data));

        }
        return null;
    }*/

    public String getInputStream(String url){
        // 通过url获取输入流
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(url != null && token != null){
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + token);// 设置密钥

            HttpEntity httpEntity = new HttpEntity(headers);
            ResponseEntity<byte[]> responseEntity = restTemplate.exchange(url, HttpMethod.GET, httpEntity, byte[].class);
            //获取entity中的数据
            byte[] body = responseEntity.getBody();
            return new String(Base64.getEncoder().encode(body));
//            FileOutputStream fileOutputStream = null;
//            try {
//                fileOutputStream = new FileOutputStream(new File("C:\\Users\\46075\\Desktop\\新建文件夹 (4)\\1.jpg"));
//                try {
//                    fileOutputStream.write(body);
//                    //关闭流
//                    fileOutputStream.close();
//
//
//                } catch (IOException e) {
//                    e.printStackTrace();
//                }
//
//            } catch (FileNotFoundException e) {
//                e.printStackTrace();
//            }

        }
        return null;
    }

    public static boolean generateImage(String photo,String imagePath){
        if(photo == null){
            return false;
        }
        // Base解码
        try {
            photo = photo.replaceAll("\r\n","");
            photo = photo.replaceAll(" +","+");

            byte[] bytes = Base64.getDecoder().decode(photo);
            for(int i= 0; i < bytes.length; i++){
                if(bytes[i] < 0){
                    bytes[i] += 256;
                }
            }
            // 生成图片
            OutputStream out = new FileOutputStream(imagePath);
            out.write(bytes);
            out.flush();
            out.close();
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

}
