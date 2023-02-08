package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.mapper.nspm.RoomProgramMapper;
import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.core.utils.CommUtils;
import com.metoo.nspm.core.utils.file.FileUtil;
import com.metoo.nspm.dto.RoomProgramDto;
import com.metoo.nspm.entity.nspm.*;
import com.metoo.nspm.vo.Result;
import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@Transactional
public class RoomProgramServiceImpl implements IRoomProgramService {

    @Autowired
    private RoomProgramMapper roomProgramMapper;
    @Autowired
    private ILiveRoomService liveRoomService;
    @Autowired
    private ISysConfigService sysConfigService;
    @Autowired
    private IGradeService gradeService;
    @Autowired
    private ICourseService courseService;
    @Autowired
    private IAccessoryService accessoryService;

    @Override
    public RoomProgram findObjById(Long id) {
        return this.roomProgramMapper.findObjById(id);
    }

    @Override
    public List<RoomProgram> getRoomProgram(Map<String, Object> params) {
        return this.roomProgramMapper.findObjByPage(params);
    }

    @Override
    public int getAccountByTotal() {
        return this.roomProgramMapper.findAccountByTotal();
    }

    @Override
    public Page<RoomProgram> query(RoomProgramDto dto) {
        if(dto == null){
            dto = new RoomProgramDto();
        }
        Page<RoomProgram> page = PageHelper.startPage(dto.getCurrentPage(), dto.getPageSize());

        this.roomProgramMapper.query(dto);
        return page;
    }

    @Override
    public Object save(RoomProgram instance) {
        if(instance != null){
            if(StringUtils.isEmpty(instance.getTitle())){
                //return new Result(400, "The title cannot be empty");
                SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddhhmmss");
                String formatDate  = sdf.format(new Date());
                instance.setTitle(formatDate);
            }
            // 时间判断
            if(instance.getBeginTime() == null){
                instance.setBeginTime(new Date());
            }
 /*           if(instance.getBeginTime() != null){
                if(instance.getEndTime() != null){
                    if(instance.getBeginTime().after(instance.getEndTime())){
                        return new Result(400, "The start time cannot be greater than the end time");
                    }
                }else{
                    return new Result(400, "Please select zabbix end time");
                }
            }else{
                return new Result(400, "Please select zabbix start time");
            }*/
           /* int flag = this.roomProgramMapper.creatRoomProgram(instance);
            if(flag == 1){
                return new Result(200, "Successfully");
            }else{
                return new Result(500, "Insert error");
            }*/
            try {
        /*        Date date = new Date();
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
                String df = sdf.format(date);
                String bindCode = df + CommUtils.randomString(6);// 推流码
                instance.setBindCode(bindCode);*/
                this.roomProgramMapper.insert(instance);
                return new Result(200, "Successfully");
            } catch (Exception e) {
                e.printStackTrace();
                return new Result(500, "Insert error");
            }
        }else{
            return new Result(400, "Params error");
        }
    }

    @Override
    public boolean save(RoomProgramDto instance) {
        User user = ShiroUserHolder.currentUser();
        // boolean flag = user.getUserRole() == null ? false : user.getUserRole().equals("ADMIN");

        if(StringUtils.isEmpty(instance.getUserName())){
            instance.setUserId(user.getId());
            instance.setUserName(user.getUsername());
        }
        RoomProgram obj = null;
        if(instance.getId() == null){
            obj = new RoomProgram();

        }else{
            obj = this.roomProgramMapper.findObjById(instance.getId());
        }
        BeanUtils.copyProperties(instance, obj);
        Grade grade = this.gradeService.getObjById(instance.getGrade_id());
        if(grade != null){
            obj.setGrade(grade);
            obj.setGradeName(grade.getName());
        }
        Course course = this.courseService.getObjById(instance.getCourse_id());
        if(course != null){
            obj.setCourse(course);
            obj.setCourseName(course.getName());
        }
        if(StringUtils.isEmpty(instance.getTitle())){
            SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddhhmmss");
            String formatDate  = sdf.format(new Date());
            obj.setTitle(formatDate);
        }
        if(StringUtils.isEmpty(instance.getLecturer())){
            obj.setLecturer(user.getUsername());
        }
       /* LiveRoom liveRoom = this.liveRoomService.getObjById(instance.getRoomId());
        if(liveRoom != null){
            obj.setRoomId(liveRoom.getId());
        }*/

        Map params = new HashMap();
        params.put("currentPage", 0);
        params.put("pageSize", 1);
        params.put("userId", user.getId());
        List<LiveRoom> liveRoomList = this.liveRoomService.findObjByMap(params);
        if(liveRoomList.size() > 0){
            obj.setRoomId(liveRoomList.get(0).getId());
        }
        Accessory accessory = this.accessoryService.getObjById(instance.getCover());
        if(accessory != null){
            obj.setCover(accessory.getId());
        }

        if(obj != null){
            if(obj.getId() == null){
                obj.setAddTime(new Date());
                obj.setUser(user);
                obj.setUserId(user.getId());
                obj.setUserName(user.getUsername());
                try {
                    this.roomProgramMapper.insert(obj);
                    return true;
                } catch (Exception e) {
                    e.printStackTrace();
                    return false;
                }
            }else{
                try {
                    this.roomProgramMapper.update(obj);
                    return true;
                } catch (Exception e) {
                    e.printStackTrace();
                    return false;
                }
            }
        }
        return false;
    }

    @Override
    public boolean update(RoomProgram instance) {
       try {
           this.roomProgramMapper.update(instance);
           return true;
       } catch (Exception e) {
           e.printStackTrace();
           return false;
       }
    }

    /**
     * 删除直播，并清空当前目录ts文件，修改当前目录权限
     * @param id
     * @return
     */
    @Override
    public int delete(Long id) {
        // 修改节目权限以及清楚多余ts文件
        RoomProgram roomProgram = this.roomProgramMapper.findObjById(id);
        if(roomProgram != null){
            if(roomProgram.getStatus() == 1){
                LiveRoom liveRoom = this.liveRoomService.getObjById(roomProgram.getRoomId());
                if(liveRoom != null){
                    String bindCode = liveRoom.getBindCode();
                    SysConfig SysConfig = this.sysConfigService.select();
                    String path =  SysConfig.getPath() + bindCode;
               /* FileUtil.delFileTs(path);
                 String m3u8 = path + File.separator + "index.m3u8";*/
                    FileUtil.delFile(path);
                }
            }
        }
        return this.roomProgramMapper.delete(id);
    }

    @Override
    public Object programLiveRoom(RoomProgram instance) {
        if(instance != null){
            List<LiveRoom> liveRoomList = this.liveRoomService.findAllLiveRoom();
            boolean flag = true;
            LiveRoom room = null;
            if(liveRoomList.size() < 1){
                room = new LiveRoom();
                room.setAddTime(new Date());
                room.setTitle("默认直播间");
                room.setManager("admin");
                room.setInfo("默认直播间");
                room.setIsEnable(1);
                Date date = new Date();
                SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd");
                String df = sdf.format(date);
                String bindCode = df + CommUtils.randomString(6);// 推流码
                room.setBindCode(bindCode);
                //rtmp://lk.soarmall.com:1935/hls
                SysConfig SysConfig = this.sysConfigService.select();
                String rtmp = CommUtils.getRtmp(SysConfig.getIp(), bindCode);
                String obsRtmp = CommUtils.getObsRtmp(SysConfig.getIp());
                String path =  SysConfig.getPath() + File.separator + bindCode;
                room.setRtmp(rtmp);
                room.setObsRtmp(obsRtmp);
                try {
                    FileUtil.storeFile(path);
                   FileUtil.possessor(path);
                } catch (IOException e) {
                    e.printStackTrace();
                }
                try {
                    this.liveRoomService.save(room);
                } catch (Exception e) {
                    e.printStackTrace();
                    flag = false;
                }
            }else{
                room = liveRoomList.get(0);
            }
            if(true){
                if(StringUtils.isEmpty(instance.getTitle())){
                    //return new Result(400, "The title cannot be empty");
                    instance.setTitle(CommUtils.formatTime("yyyyMMddHHmmss",new Date()));
                }
                if(StringUtils.isEmpty(instance.getLecturer())){
                    //return new Result(400, "The title cannot be empty");
                    instance.setLecturer("Admin");
                }

                /*if(instance.getBeginTime().after(new Date())){
                    instance.setBeginTime(new Date());
                }*/
                instance.setBeginTime(new Date());

                /*if(instance.getBeginTime() != null){
                    if(null != instance.getEndTime()){
                        if(instance.getBeginTime().after(instance.getEndTime())){
                            return new Result(400, "The start time cannot be greater than the end time");
                        }
                    }else{
                        return new Result(400, "Please select zabbix end time");
                    }
                }else{
                    return new Result(400, "Please select zabbix start time"); }*/
                try {
                    //Date date = new Date();
                    //SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd");
                    //String df = sdf.format(date);
                    //String bindCode = df + CommUtils.randomString(6);// 推流码
                    //instance.setBindCode(bindCode);
                    instance.setRoomId(room.getId());
                    instance.setAddTime(new Date());
                    //rtmp://lk.soarmall.com:1935/hls
               /*     List<SysConfig> sysConfigList = this.sysConfigService.select();
                    String rtmp = "rtmp://" + sysConfigList.get(0).getIp() + ":1935" + "/hls/" + bindCode;
                    instance.setRtmp(rtmp);*/
                    this.roomProgramMapper.insert(instance);
                    return new Result(200, "Successfully");
                } catch (Exception e) {
                    e.printStackTrace();
                    return new Result(500, "Insert error");
                }
            }else{
                return new Result(500, "Create error");
            }
        }else{
            return new Result(500, "Create error");
        }
    }

    @Override
    public List<RoomProgram> findObjByCondition(Map<String, Object> params) {
        return this.roomProgramMapper.condition(params);
    }

    @Override
    public List<RoomProgram> findRoomProgramByLiveRoomId(Map<String, Object> params) {
        return this.roomProgramMapper.findObjByLiveRoomId(params);
    }

    @Override
    public List<RoomProgram> liveStatus(Map<String, Object> params) {

        return this.roomProgramMapper.livestatus(params);
    }

}
