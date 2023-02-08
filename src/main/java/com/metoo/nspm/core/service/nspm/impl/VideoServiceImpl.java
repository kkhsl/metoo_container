package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.mapper.nspm.VideoMapper;
import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.core.utils.file.FileUtil;
import com.metoo.nspm.dto.VideoDto;
import com.metoo.nspm.entity.nspm.*;
import com.metoo.nspm.vo.Result;
import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.File;
import java.io.Serializable;
import java.util.*;

@Service
@Transactional
public class VideoServiceImpl implements IVideoService {

    @Autowired
    private VideoMapper videoMapper;
    @Autowired
    private IGradeService gradeService;
    @Autowired
    private ISysConfigService configService;
    @Autowired
    private IAccessoryService accessoryService;
    @Autowired
    private ICourseService courseService;
    @Autowired
    private ILiveRoomService liveRoomService;
    @Autowired
    private IResService resService;
    @Autowired
    private IUserService userService;

    @Override
    public Video getObjById(Long id) {
        return this.videoMapper.get(id);
    }

    @Override
    public Video selectPrimaryById(Long id) {
        return this.videoMapper.videoUnit(id);
    }

    @Override
    public Page<Video> query(VideoDto dto) {
        Page<Video> page = PageHelper.startPage(dto.getCurrentPage(), dto.getPageSize());
        this.videoMapper.query(dto);
        return page;
    }

    @Override
    public List<Video> findObjBuLiveRoomId(Long id) {
        return this.videoMapper.findObjBuLiveRoomId(id);
    }

    @Override
    public List<Video> findObjByMap(Map params) {
        Page<Video> page = PageHelper.startPage((Integer)params.get("currentPage"), (Integer)params.get("pageSize"));
        this.videoMapper.findObjByMap(params);
        return page;
    }

    @Override
    public Result save(VideoDto instance) {
        User user = ShiroUserHolder.currentUser();
        int code = 200;
            String msg = "Successfully";
            Video video = null;
            if(instance != null){
                if(instance.getName() != null && !instance.getName().equals("")){
                    if(instance.getId() == null){
                        video = new Video();
                    }else{
                        video = this.videoMapper.get(instance.getId());
                        if(!video.getUserId().equals(user.getId())){
                            return new Result(400, "您未拥有这个视频资源");
                        }
                    }
                    if(instance.getGrade_id()!= null){
                        Grade grade = this.gradeService.getObjById(instance.getGrade_id());
                        if(grade != null){
                            video.setGrade(grade);
                        }else{
                            return new Result(400, "Grade params error");
                        }
                    }
               /* // 使用帐号默认直播间
                if(instance.getLiveRoomId() != null){
                        LiveRoom liveRoom = this.liveRoomService.getObjById(instance.getLiveRoomId());
                        if(liveRoom != null){
                            video.setLiveRoom(liveRoom);
                            video.setLiveRoomId(liveRoom.getId());
                        }
                    }*/
                    Map params = new HashMap();
                    params.put("currentPage", 0);
                    params.put("pageSize", 1);
                    params.put("userId", user.getId());
                    List<LiveRoom> liveRoomList = this.liveRoomService.findObjByMap(params);
                    if(liveRoomList.size() > 0){
                        video.setLiveRoomId(liveRoomList.get(0).getId());
                        video.setLiveRoom(liveRoomList.get(0));
                    }

                    if(instance.getCourse_id() != null){
                        Course course = this.courseService.getObjById(instance.getCourse_id());
                        if(course != null){
                            video.setCourse(course);
                        }else{
                            return new Result(400, "Course params error");
                        }
                    }
                    // 视频审核
                    SysConfig config = this.configService.select();
                    if(config.getVideoAudit()==0){
                        video.setStatus(1);
                    }else{
                        video.setStatus(0);
                        Collection<String> resList = this.resService.findPermissionByUserId(user.getId());
                        if(resList.size() > 0){
                            if(resList.contains("LK:VIDEO:MANAGER")){
                                video.setStatus(1);
                            }
                        }
                    }
                    Accessory accessoryPhoto = this.accessoryService.getObjById(instance.getPhotoId());
                    if(accessoryPhoto != null){
                        video.setAccessory(accessoryPhoto);
                    }
                    Accessory accessoryVideo = this.accessoryService.getObjById(instance.getVideoId());
                    if(accessoryVideo != null){
                        video.setVideo(accessoryVideo);
                    }
                    video.setAddTime(new Date());
                    video.setBeginTime(instance.getBeginTime());
                    video.setEndTime(instance.getEndTime());
                    video.setDescribe(instance.getDescribe());
                    video.setDisplay(instance.getDisplay());
                    video.setUserId(user.getId());
                    video.setUserName(user.getUsername());
                    video.setMessage(instance.getMessage());
                    video.setName(instance.getName());
                    video.setRoomProgramId(instance.getRoomProgramId());
                    video.setType(instance.getType());
                    video.setSequence(instance.getSequence());
                    try {
                        if(instance.getId() == null){
                            this.videoMapper.insert(video);
                        }else{
                           int status =  video.getStatus() == -1 ? 0 : video.getStatus();
                           video.setStatus(status);
                           video.setMessage("");
                           this.videoMapper.update(video);
                        }
                        return new Result(200, "Successfully");
                    } catch (Exception e) {
                        e.printStackTrace();
                        return new Result(500, "Fail to save");
                    }
            }else{
                return new Result(400, "Params error");
            }
        }else{
            return new Result(400, "Params error");
        }
    }

    @Override
    public boolean save(Video instance) {
        if(instance != null){
            try {
                instance.setAddTime(new Date());
                this.videoMapper.insert(instance);
                return true;
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }
        return false;
    }

    @Override
    public boolean update(VideoDto instance) {
       Video video = new Video();
       BeanUtils.copyProperties(instance, video);
       try {
           this.videoMapper.update(video);
           return true;
       } catch (Exception e) {
           e.printStackTrace();
           return false;
       }
    }

    @Override
    public boolean update(Video instance) {
        try {
            this.videoMapper.update(instance);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public boolean delete(Long id) {
        Video video = this.videoMapper.get(id);
        if(video != null){
            SysConfig configs = this.configService.select();
            String path = configs.getPhotoFilePath();
            try {
                this.videoMapper.delete(id);
                Accessory vo = video.getVideo();
                if(vo != null){
                    String video_path = configs.getVideoFilePath();
                    video_path = video_path + File.separator + vo.getA_name();
                    File file = new File(video_path);
                    FileUtil.deleteAll(file);
                    this.accessoryService.delete(vo.getId());
                }
                Accessory photo = video.getAccessory();
                if(photo != null){
                    path = path + File.separator + photo.getA_name();
                    File file = new File(path);
                    if(file.exists()){
                        file.delete();
                    }
                    this.accessoryService.delete(photo.getId());
                }
                return true;
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }
        return false;
    }

    @Override
    public boolean batchDelete(List<Serializable> ids) {
        return false;
    }

    @Override
    public List<Video> queryAll(Integer currentPage, Integer pageSize) {
        // 分页插件: 查询第1页，每页10行
        Page<Video> page = PageHelper.startPage(currentPage, pageSize);

        List<Video> videos = this.videoMapper.selectAll();

        // 数据表的总行数
        long total =  page.getTotal();

        return videos;
    }

}
