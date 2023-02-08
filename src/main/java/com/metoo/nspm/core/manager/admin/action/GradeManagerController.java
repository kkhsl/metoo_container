package com.metoo.nspm.core.manager.admin.action;

import com.metoo.nspm.core.manager.admin.tools.ShiroUserHolder;
import com.metoo.nspm.core.service.nspm.*;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.core.utils.query.PageInfo;
import com.metoo.nspm.dto.CourseDto;
import com.metoo.nspm.dto.GradeDto;
import com.metoo.nspm.entity.nspm.*;
import com.metoo.nspm.req.GradeReq;
import com.metoo.nspm.vo.Result;
import com.github.pagehelper.Page;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RequiresPermissions("LK:GRADE:MANAGER")
@Api("年级管理")
@RestController
@RequestMapping("/admin/grade")
public class GradeManagerController {

    @Autowired
    private IGradeService gradeService;
    @Autowired
    private IAccessoryService accessoryService;
    @Autowired
    private ISysConfigService configService;
    @Autowired
    private IVideoService videoService;
    @Autowired
    private IRoomProgramService roomProgramService;

//    @RequiresPermissions("ADMIN:GRADE:LIST")
    @ApiOperation("年级列表")
    @RequestMapping("/list")
    public Object list(@RequestBody CourseDto dto){
        User user = ShiroUserHolder.currentUser();
        if(dto.getCurrentPage() == null || dto.getCurrentPage() < 1){
            dto.setCurrentPage(1);
        }
        if(dto.getPageSize() == null || dto.getPageSize() < 1 ){
            dto.setPageSize(15);
        }
        if(user == null){
            return ResponseUtil.unlogin();
        }
        Map data = new HashMap();

        Map params = new HashMap();
        params.put("pageSize", dto.getPageSize());
        params.put("startRow", (dto.getCurrentPage() ));
        Page<Grade> page = this.gradeService.query(params);
        return ResponseUtil.ok(new PageInfo<Grade>(page));
    }

//    @RequiresPermissions("ADMIN:GRADE:UPDATE")
    @ApiOperation("年级更新")
    @PutMapping("/update")
    public Object update(@RequestBody GradeDto gradeDto){
        Grade grade = this.gradeService.modify(gradeDto.getId());
        if(grade != null){
           return ResponseUtil.ok(grade);
        }
        return ResponseUtil.ok();
    }

//    @RequiresPermissions("ADMIN:GRADE:SAVE")
    @ApiOperation("年级添加")
    @PostMapping("/save")
    public Object save(GradeDto gradeDto,
                       @RequestParam(value = "file", required = false) MultipartFile file){
        if (file != null && file.getSize() > 0) {
            Accessory accessory = this.upload(file, 0);
            gradeDto.setAccessory(accessory);
        }
        return this.gradeService.save(gradeDto);
    }

    public Accessory upload(@RequestParam(required = false) MultipartFile file, int type){
        SysConfig configs = this.configService.select();
        String uploaFilePath = configs.getUploadFilePath();
        String path = configs.getVideoFilePath();
        if(type == 0){
            path = configs.getPhotoFilePath();
            uploaFilePath = uploaFilePath + File.separator + "photo";
        }else{
            uploaFilePath = uploaFilePath + File.separator + "vedio";
        }
        String originalName = file.getOriginalFilename();
        String fileName = UUID.randomUUID().toString().replace("-", "");
        String ext = originalName.substring(originalName.lastIndexOf("."));
        String picNewName = fileName + ext;
        String imgRealPath = path + File.separator + picNewName;

        java.io.File imageFile = new File(imgRealPath);
        if (!imageFile.getParentFile().exists()) {
            imageFile.getParentFile().mkdirs();
        }
        try {
            file.transferTo(imageFile);
            Accessory accessory = new Accessory();
            accessory.setA_name(picNewName);
            accessory.setA_path(uploaFilePath);
            accessory.setA_ext(ext);
            accessory.setA_size((int)file.getSize());
            accessory.setType(type);
            this.accessoryService.save(accessory);
            return accessory;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

//    @RequiresPermissions("ADMIN:GRADE:DELETE")
    @ApiOperation("年级删除")
    @RequestMapping("/delete")
    public Object delete(@RequestBody GradeDto dto){
        Grade grade = this.gradeService.getObjById(dto.getId());
        if(grade == null){
            return new Result(400, "Parameter error");
        }

        SysConfig configs = this.configService.select();
        String path = configs.getPhotoFilePath();
        Accessory accessory = grade.getAccessory();
        if(accessory != null){
            path = path + File.separator + accessory.getA_name();
            File file = new File(path);
            if(file.exists()){
                file.delete();
            }
            this.accessoryService.delete(accessory.getId());
        }
        // 清除关联项
        Map map = new HashMap();
        map.put("grade_id", grade.getId());
        map.put("currentPage", 0);
        map.put("pageSize", 0);
        List<Video> videoList = this.videoService.findObjByMap(map);
        for(Video video : videoList){
            video.setGrade(null);
            this.videoService.update(video);
        }
        List<RoomProgram> roomProgramList = this.roomProgramService.findObjByCondition(map);

        for(RoomProgram roomProgram : roomProgramList){
            roomProgram.setGrade(null);
            roomProgram.setGradeName(null);
            this.roomProgramService.update(roomProgram);
        }

        if(this.gradeService.delete(grade.getId())){
            return ResponseUtil.ok();
        }
        return ResponseUtil.prohibitDel();
    }

//    @RequiresPermissions("ADMIN:GRADE:CHANGE")
    @ApiOperation("年级修改")
    @PutMapping("/change")
    public Object change(@RequestBody GradeReq req){
        if(req.getId() != null && !req.getId().equals("")){
            Grade grade = this.gradeService.getObjById(req.getId());
            int display = grade.getDisplay() == 1 ? 0 : 1;
            grade.setDisplay(display);
            Accessory accessory = this.accessoryService.getObjById(req.getAccessory());
            if(accessory != null){
                grade.setAccessory(accessory);
            }
            if(grade != null){
                this.gradeService.update(grade);
                return ResponseUtil.ok();
            }
        }
        return ResponseUtil.badArgument();
    }

}
