package com.metoo.nspm.core.service.nspm.impl;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.mapper.nspm.TopologyHistoryMapper;
import com.metoo.nspm.core.mapper.nspm.TopologyMapper;
import com.metoo.nspm.core.service.nspm.ILinkService;
import com.metoo.nspm.core.service.nspm.ITopologyService;
import com.metoo.nspm.dto.TopologyDTO;
import com.metoo.nspm.entity.nspm.Link;
import com.metoo.nspm.entity.nspm.Topology;
import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import com.metoo.nspm.entity.nspm.User;
import org.nutz.json.Json;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@Transactional
public class TopologyServiceImpl implements ITopologyService {

    @Autowired
    private TopologyMapper topologyMapper;
    @Autowired
    private TopologyHistoryMapper topologyHistoryMapper;
    @Autowired
    private ILinkService linkService;

    @Override
    public Topology selectObjById(Long id) {
        return this.topologyMapper.selectObjById(id);
    }

    @Override
    public Topology selectObjBySuffix(String name) {
        return this.topologyMapper.selectObjBySuffix(name);
    }

    @Override
    public Page<Topology> selectConditionQuery(TopologyDTO instance) {
        if(instance == null){
            instance = new TopologyDTO();
        }
        Page<Topology> page = PageHelper.startPage(instance.getCurrentPage(), instance.getPageSize());

        this.topologyMapper.selectConditionQuery(instance);
        return page;
    }

    @Override
    public List<Topology> selectObjByMap(Map params) {
        return this.topologyMapper.selectObjByMap(params);
    }

    @Override
    public List<Topology> selectTopologyByMap(Map params) {
        return this.topologyMapper.selectTopologyByMap(params);
    }

    @Override
    public int save(Topology instance) {
        if(instance.getId() == null){
            instance.setAddTime(new Date());
        }else{
            instance.setUpdateTime(new Date());
        }
        if(instance.getContent() != null && !instance.getContent().equals("")){
            // 解析content 并写入uuid
            Object content = this.writerUuid(instance.getContent());
            instance.setContent(content);
            this.syncLinkManager(instance.getContent());
        }
        if(instance.getId() == null){
            try {
               int i = this.topologyMapper.save(instance);
                if(i >= 1){
                    try {
                        Calendar cal = Calendar.getInstance();
                        instance.setAddTime(cal.getTime());
                        this.topologyHistoryMapper.save(instance);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                return instance.getId().intValue();
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }else{
            try {
                int i = this.topologyMapper.update(instance);
                if(i >= 1){
                    try {
                        Calendar cal = Calendar.getInstance();
                        instance.setAddTime(cal.getTime());
                        this.topologyHistoryMapper.save(instance);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                return i;
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }
    }

    // 为拓扑图连线增加Uuid
    public Object writerUuid(Object param){
        if (param != null) {
            Map content = JSONObject.parseObject(param.toString(), Map.class);
            JSONArray links = this.getLinks(content);
            if(links.size() > 0){
                List list = this.setUuid(links);
                content.put("links", list);
                return JSON.toJSONString(content);
            }
        }
        return param;
    }

    // 同步到链路管理
    public Object syncLinkManager(Object param){
        if (param != null) {
            Map content = JSONObject.parseObject(param.toString(), Map.class);
            JSONArray links = this.getLinks(content);
            if(links.size() > 0){
                List<Link> linkList = new ArrayList();
                for (Object object : links) {
                    Map link = JSONObject.parseObject(object.toString(), Map.class);
                    Map params = new HashMap();
                    if(link.get("fromNode") == null || link.get("toNode") == null){
                        continue;
                    }
                    Map fromNode = JSONObject.parseObject(link.get("fromNode").toString(), Map.class);
                    params.put("startIp", fromNode.get("ip"));
                    Map toNode = JSONObject.parseObject(link.get("toNode").toString(), Map.class);
                    params.put("endIp", toNode.get("ip"));
                    List<Link> linkList1 = this.linkService.selectObjByMap(params);
                    if(linkList1.size() == 0){
                        Link link1 = new Link();
                        link1.setAddTime(new Date());
                        link1.setStartDevice(fromNode.get("name").toString());
                        link1.setStartInterface(link.get("fromPort").toString());
                        link1.setStartIp(fromNode.get("ip").toString());
                        link1.setEndDevice(toNode.get("name").toString());
                        link1.setEndInterface(link.get("toPort").toString());
                        link1.setEndIp(toNode.get("ip").toString());
                        User user = ShiroUserHolder.currentUser();
                        if(link1.getGroupId() == null){
                            link1.setGroupId(user.getGroupId());
                        }
                        linkList.add(link1);
                    }

                }
                if(linkList.size() > 0){
                    try {
                        this.linkService.batchesInsert(linkList);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        }
        return param;
    }

    public JSONArray getLinks(Map content){
        if (content != null) {
            if (content.get("links") != null) {
                JSONArray links = JSONArray.parseArray(content.get("links").toString());
                if (links.size() > 0) {
                    return links;
                }
            }
        }
        return new JSONArray();
    }

    public List setUuid(JSONArray links){
        List list = new ArrayList();
        for (Object object : links) {
            Map link = JSONObject.parseObject(object.toString(), Map.class);
            if(link.get("uuid") == null || link.get("uuid").equals("")){
                link.put("uuid", UUID.randomUUID());
            }
            list.add(link);
        }
        return list;
    }

    @Override
    public int update(Topology instance) {
        try {
            return this.topologyMapper.update(instance);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    @Override
    public int delete(Long id) {
        try {
            return this.topologyMapper.delete(id);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    @Override
    public Long copy(Topology instance) {
        try {
            int i = this.topologyMapper.copy(instance);
            if(i >= 1){
                return instance.getId();
            }
            return null;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
