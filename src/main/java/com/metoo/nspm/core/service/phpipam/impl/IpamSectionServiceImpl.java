package com.metoo.nspm.core.service.phpipam.impl;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.http.IpamApiUtil;
import com.metoo.nspm.core.service.phpipam.IpamSectionService;
import org.springframework.stereotype.Service;

@Service
public class IpamSectionServiceImpl implements IpamSectionService {

    @Override
    public JSONObject sections(Integer id, String path) {
        String url = "/sections/";
        if(id != null){
            url += id;
        }
        if(path != null){
            url += "/" + path;
        }
        IpamApiUtil base = new IpamApiUtil(url);
        return base.get();
    }

    @Override
    public Integer getSectionsId() {
        String url = "/sections/";
        IpamApiUtil base = new IpamApiUtil(url);
         JSONObject section = base.get();
        if(section.getBoolean("success")){
            JSONArray datas = JSONArray.parseArray(section.getString("data"));
            if(datas.size() > 0){
                JSONObject data = JSONObject.parseObject(datas.getString(0));
                return data.getInteger("id");
            }
        }
        return null;
    }
}
