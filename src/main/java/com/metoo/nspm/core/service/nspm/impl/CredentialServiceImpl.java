package com.metoo.nspm.core.service.nspm.impl;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.mapper.nspm.CredentialMapper;
import com.metoo.nspm.core.service.nspm.ICredentialService;
import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.core.service.nspm.IUserService;
import com.metoo.nspm.core.utils.NodeUtil;
import com.metoo.nspm.dto.CredentialDTO;
import com.metoo.nspm.dto.NetworkElementDto;
import com.metoo.nspm.dto.TopoCredentialDto;
import com.metoo.nspm.entity.nspm.Credential;
import com.metoo.nspm.entity.nspm.NetworkElement;
import com.metoo.nspm.entity.nspm.SysConfig;
import com.metoo.nspm.entity.nspm.User;
import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@Transactional
public class  CredentialServiceImpl implements ICredentialService {

    @Autowired
    private CredentialMapper credentialMaaper;
    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private NodeUtil nodeUtil;
    @Autowired
    private IUserService userService;


    @Override
    public Credential getObjById(Long id) {
        return this.credentialMaaper.getObjById(id);
    }

    @Override
    public Credential getObjByName(String name) {
        return this.credentialMaaper.getObjByName(name);
    }

    @Override
    public List<Credential> query() {
        return null;
    }

    @Override
    public int save(Credential instance) {
        if(instance.getId() == null || instance.getId().equals("")){
            instance.setAddTime(new Date());
            String uuid = UUID.randomUUID().toString().replace("-", "");
            instance.setUuid(uuid);
            User user = ShiroUserHolder.currentUser();
            instance.setUserId(user.getId());
        }
        if(instance.getId() == null || instance.getId().equals("")){
            try {
                return this.credentialMaaper.save(instance);
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }else{
            try {
                return this.credentialMaaper.update(instance);
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }
    }

    @Override
    public int update(Credential instance) {
        return this.credentialMaaper.update(instance);
    }

    @Override
    public int delete(Long id) {
        return this.credentialMaaper.delete(id);
    }

    @Override
    public int batchesDel(Long[] ids) {
        return this.credentialMaaper.batchesDel(ids);
    }

    @Override
    public Map<String, String> getUuid(TopoCredentialDto dto) {
        SysConfig sysConfig = this.sysConfigService.select();
        String token = sysConfig.getNspmToken();
        if(token != null){
            String url = "/push/credential/getall";
            Object result = this.nodeUtil.postBody(dto, url, token);
            JSONObject json = JSONObject.parseObject(result.toString());
            if(json.get("content") != null){
                JSONObject content = JSONObject.parseObject(json.get("content").toString());
                if(content.get("list") != null) {
                    List list = new ArrayList();
                    JSONArray arrays = JSONArray.parseArray(content.get("list").toString());
                    for (Object array : arrays) {
                        JSONObject credential = JSONObject.parseObject(array.toString());
                        if(credential.get("uuid") != null && credential.get("name").equals(dto.getName())){
                            Map map = new HashMap();
                            map.put("uuid", credential.get("uuid").toString());
                            map.put("credentialId", credential.get("id").toString());
                            return map;
                        }
                    }
                }
            }

    }
     return null;
    }

    @Override
    public Page<Credential> getObjsByLevel(Credential instance) {
        if(instance.getBranchLevel() == null || instance.getBranchLevel().equals("")){
            User currentUser = ShiroUserHolder.currentUser();
            User user = this.userService.findByUserName(currentUser.getUsername());
            instance.setBranchLevel(user.getGroupLevel());
        }
        Page<Credential> page = PageHelper.startPage(instance.getCurrentPage(), instance.getPageSize());
        this.credentialMaaper.getObjsByLevel(instance);
        return page;
    }

    @Override
    public List<Credential> getAll() {
        return this.credentialMaaper.getAll();
    }

    @Override
    public Page<Credential> selectObjByConditionQuery(CredentialDTO dto) {
        if(dto == null){
            dto = new CredentialDTO();
        }
        Page<Credential> page = PageHelper.startPage(dto.getCurrentPage(), dto.getPageSize());
        this.credentialMaaper.selectConditionQuery(dto);
        return page;
    }
}
