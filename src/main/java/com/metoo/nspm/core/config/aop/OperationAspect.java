package com.metoo.nspm.core.config.aop;

import com.alibaba.fastjson.JSONObject;
import com.metoo.nspm.core.config.annotation.OperationLogAnno;
import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.entity.nspm.*;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.Signature;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.nutz.json.Json;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;

import java.lang.reflect.Method;
import java.util.*;

@Slf4j
@Aspect
@Configuration
public class OperationAspect {

    @Autowired
    private IRsmsDeviceService rsmsDeviceService;
    @Autowired
    private IDeviceTypeService deviceTypeService;
    @Autowired
    private IPlantRoomService plantRoomService;
    @Autowired
    private IRackService rackService;
    @Autowired
    private IChangeLogService changeLogService;
    @Autowired
    private IVirtualServerService virtualServerService;
    @Autowired
    private IOperationSystemService operationSystemService;
    @Autowired
    private IVirtualTypeService virtualTypeService;

    //切点
    @Pointcut("@annotation(com.metoo.nspm.core.config.annotation.OperationLogAnno)")
    private void cutMethod() {

    }

    @Before("cutMethod() && @annotation(operationLogAnno)")
    public void device(JoinPoint joinPoint, OperationLogAnno operationLogAnno) throws Throwable {
//        System.out.println("res" + res);
        // 获取方法名
        String methodName = joinPoint.getSignature().getName();
        // 反射获取目标类
        Class<?> targetClass = joinPoint.getTarget().getClass();

        Signature signature = joinPoint.getSignature();
        MethodSignature methodSignature = (MethodSignature) signature;
        Method method = methodSignature.getMethod();

        //4. 获取方法的参数 一一对应
        Object[] args = joinPoint.getArgs();
        if(args.length > 0){
            if(operationLogAnno.name().equals("device")){
                this.parse(args[0]);
            }
            if(operationLogAnno.name().equals("virtualServer")){
                this.parseVirtualServer(args[0]);
            }
            }
        }

    public void parse(Object object){
        RsmsDevice rsmsDevice = Json.fromJson(RsmsDevice.class, JSONObject.toJSONString(object));
        if(rsmsDevice.getId() != null){
            RsmsDevice obj = this.rsmsDeviceService.getObjById(rsmsDevice.getId());
            ChangeLog changeLog = new ChangeLog();
            changeLog.setObjectName(rsmsDevice.getName());
            changeLog.setObjectId(rsmsDevice.getId());
            changeLog.setDeviceName(rsmsDevice.getName());
            DeviceType type =this.deviceTypeService.selectObjById(rsmsDevice.getDeviceTypeId());
            if(type != null){
                changeLog.setDeviceType(type.getName());
            }
            changeLog.setDeviceId(obj.getId());
            changeLog.setChangeReasons(rsmsDevice.getChangeReasons());
            PlantRoom plantRoom = this.plantRoomService.getObjById(rsmsDevice.getPlantRoomId());
            if(plantRoom != null){
                rsmsDevice.setPlantRoomName(plantRoom.getName());
            }
            Rack rack = this.rackService.getObjById(rsmsDevice.getRackId());
            if(rack != null){
                rsmsDevice.setRackName(rack.getName());
            }
            DeviceType deviceType = this.deviceTypeService.selectObjById(rsmsDevice.getDeviceTypeId());
            if(deviceType != null){
                rsmsDevice.setDeviceTypeName(deviceType.getName());
            }
            rsmsDevice.setPlantRoomId(obj.getPlantRoomId());
            rsmsDevice.setRackId(obj.getRackId());
            rsmsDevice.setDeviceTypeId(obj.getDeviceTypeId());

            JSONObject current = JSONObject.parseObject(Json.toJson(rsmsDevice));
            JSONObject old = JSONObject.parseObject(Json.toJson(obj));
            List list = new ArrayList();
            current.put("changeReasons", null);
            for (Object key : current.keySet()){
                Map map = new HashMap();
                if(old.get(key) != null && !old.get(key).equals("") &&  current.get(key) != null && !current.get(key).equals(old.get(key))){
                    map.put("key",key);
                    map.put("old", old.get(key) == null ? "" : old.get(key));
                    map.put("new",current.get(key));
                    list.add(map);
                }
            }
            changeLog.setContent(Json.toJson(list));
            this.changeLogService.save(changeLog);
//                Map<String, JSONObject> map  = new HashMap<String, JSONObject>();
//                map.put("current", newDevice);
//                map.put("old", oldDevice);
//                return map;
        }
    }

    public void parseVirtualServer(Object object){
        VirtualServer virtualServer = Json.fromJson(VirtualServer.class, JSONObject.toJSONString(object));
        if(virtualServer.getId() != null){
            VirtualServer obj = this.virtualServerService.getObjById(virtualServer.getId());
            ChangeLog changeLog = new ChangeLog();
            changeLog.setObjectName(virtualServer.getName());
            changeLog.setObjectId(virtualServer.getId());
            changeLog.setObjectName(virtualServer.getName());
            changeLog.setObjectId(virtualServer.getId());
            changeLog.setChangeReasons(virtualServer.getChangeReasons());
            OperationSystem operationSystem = this.operationSystemService.getObjById(virtualServer.getOperation_system_id());
            if(operationSystem != null){
                obj.setOperation_system_name(operationSystem.getName());
            }
            VirtualType virtualType = this.virtualTypeService.getObjById(virtualServer.getVirtual_type_id());
            if(virtualType != null){
                obj.setVirtual_type_name(virtualType.getName());
            }
            RsmsDevice rsmsDevice = this.rsmsDeviceService.getObjById(virtualServer.getDevice_id());
            if(rsmsDevice != null){
                obj.setDevice_name(rsmsDevice.getName());
            }
            JSONObject current = JSONObject.parseObject(Json.toJson(virtualServer));
            JSONObject old = JSONObject.parseObject(Json.toJson(obj));
            current.put("changeReasons", null);
            List list = new ArrayList();
            for (Object key : current.keySet()){
                Map map = new HashMap();
                if(old.get(key) != null && !old.get(key).equals("") && current.get(key) != null && !current.get(key).equals(old.get(key))){
                    map.put("key",key);
                    map.put("old", old.get(key) == null ? "" : old.get(key));
                    map.put("new",current.get(key));
                    list.add(map);
                }
            }
            changeLog.setContent(Json.toJson(list));
            this.changeLogService.save(changeLog);
        }
    }
}
