package com.metoo.nspm.core.utils.httpclient;

import com.metoo.nspm.core.service.nspm.ISysConfigService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class UrlConvertUtil {

    @Value("${spring.profiles.active}")
    private String env;

    @Autowired
    private ISysConfigService sysConfigService;

    public String convert(String url){
        String nspmUrl = sysConfigService.select().getNspmUrl();
        String convert = "";
        String abtUrl = "";
        int indexOf = url.indexOf("/");
        if(indexOf == 0){
            indexOf = url.indexOf("/",2);
            if(indexOf > -1){
                convert = url.substring(1, indexOf);
                abtUrl = url.substring(convert.length() + 1, url.length());
            }
        }else{
            convert = url.substring(0, indexOf);
            abtUrl = url.substring(convert.length() + 1, url.length());
            url = "/" + url;
        }
        String port = "";
        switch (convert){
            case "siip":
                port = ":54002";
                break;
            case "sso":
                port = ":8090";
                break;
            case "v0":
                port = ":54201";
                break;
            case "combing":
                port = ":8087";
                break;
            case "topology-monitor":
                port = ":8888";
                break;
            case "push":
                port = ":8088";
                break;
            case "patrol":
                port = ":8089";
                break;
            case "discover":
                port = ":8099";
                break;
            case "disposal":
                port = ":8084";
                break;
            case "vmsdn":
                port = ":8085";
                break;
            case "risk":
                port = ":8086";
                break;
            case "legal":
                port = ":8091";
                break;
            case "topology-layer":
                port = ":8889";
                break;
            case "topology-api":
                port = ":topology-api";
                break;
            case "xxl-job-admin":
                port = ":8883";
                break;
            case "monit":
                port = ":5601";
            case "topology":
                port = ":54211";
                break;
            case "topology-policy":
                port = ":8890";
                break;
            default:
                break;
        }
        if(env.equals("docker")){
            return nspmUrl + port + url;
        }return nspmUrl + url;
    }
}
