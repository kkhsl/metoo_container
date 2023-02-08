package com.metoo.nspm.core.manager.admin.tools;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.dto.MonitorDto;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

/**
 * 异步调用监控方法
 */
@Component
public class MonitorTools {

    private static final String url = "http://182.61.48.214/monitor/save";

   /* @Autowired
    private RestTemplate restTemplate;*/

   /* @Async
    public void monitor(MonitorDto dto){
        if(dto != null){
            RestTemplate client = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            HttpMethod method = HttpMethod.POST;
            // 以表单的方式提交
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            //将请求头部和参数合成一个请求
            HttpEntity<MonitorDto> requestEntity = new HttpEntity<>(dto, headers);
            //执行HTTP请求，将返回的结构使用ResultVO类格式化
            ResponseEntity<String> response = client.exchange(url, method, requestEntity, String.class);

        }
    }*/

    @Async
    public void monitor(MonitorDto dto){
        if(dto != null){
            RestTemplate client = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            HttpMethod method = HttpMethod.POST;
            JSONObject postData = new JSONObject();
            // 以Json的方式提交
            headers.setContentType(MediaType.APPLICATION_JSON);

            JSONObject json = client.postForEntity(url, postData.toJSON(dto), JSONObject.class).getBody();
//            SystemTest.out.println(json.get("result"));
            //User是提前创建好的实体类，将返回的json中的result数据转换为User格式
//            Group group = json.getObject("result", User.class);

        }
    }

    public String getSHA256StrJava(String str) {
        java.security.MessageDigest messageDigest;
        String encodeStr = "";
        try {
            messageDigest = java.security.MessageDigest.getInstance("SHA-256");
            messageDigest.update(str.getBytes("UTF-8"));
            encodeStr = byte2Hex(messageDigest.digest());
        } catch (java.security.NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (java.io.UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return encodeStr;
    }

    public String byte2Hex(byte[] bytes) {
        StringBuffer stringBuffer = new StringBuffer();
        String temp = null;
        for (int i = 0; i < bytes.length; i++) {
            temp = Integer.toHexString(bytes[i] & 0xFF);
            if (temp.length() == 1) {
                // 1得到一位的进行补0操作
                stringBuffer.append("0");
            }
            stringBuffer.append(temp);
        }
        return stringBuffer.toString();
    }
}
