package com.metoo.nspm.core.manager.admin.action;

import com.metoo.nspm.core.service.nspm.ICourseService;
import com.metoo.nspm.core.service.nspm.IRoomProgramService;
import com.metoo.nspm.core.service.nspm.IVideoService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.dto.CourseDto;
import com.metoo.nspm.entity.nspm.Course;
import com.metoo.nspm.entity.nspm.RoomProgram;
import com.metoo.nspm.entity.nspm.Video;
import com.metoo.nspm.req.CourseReq;
import com.metoo.nspm.vo.Result;
import com.github.pagehelper.Page;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Api("科目管理")
@RequiresPermissions("LK:COURSE:MANAGER")
@RestController
@RequestMapping("/admin/course")
public class CourseManagerController {

    @Autowired
    private ICourseService courseService;
    @Autowired
    private IVideoService videoService;
    @Autowired
    private IRoomProgramService roomProgramService;

//    @RequiresPermissions("ADMIN:COURSE:LIST")
    @ApiOperation("科目列表")
    @RequestMapping("/list")
    public Object list(@RequestBody(required = false) CourseDto dto){
        Map data = new HashMap();
        if(dto.getCurrentPage() == null || dto.getCurrentPage() < 1){
            dto.setCurrentPage(1);
        }
        if(dto.getPageSize() == null || dto.getPageSize() < 1 ){
            dto.setPageSize(15);
        }
        Map params = new HashMap();
        params.put("pageSize", dto.getPageSize());
        params.put("startRow", (dto.getCurrentPage() ));
        Page<Course> page = this.courseService.query(params);
        data.put("obj", page.getResult());
        data.put("currentPage", page.getPageNum());
        data.put("pageSize", page.getPageSize());
        data.put("pages", page.getPages());
        data.put("total", page.getTotal());
        return new Result(200, "Successfully", data);
    }


//    @RequiresPermissions("ADMIN:COURSE:UPDATE")
    @ApiOperation("科目修改")
    @PutMapping("/update")
    public Object update(@RequestBody CourseDto courseDto){
        Map data = new HashMap();
        Course course = this.courseService.getObjById(courseDto.getId());
        if(course != null){
            data.put("obj", course);
            return ResponseUtil.query(data);
        }
        return ResponseUtil.error();
    }

    /*    @ApiOperation("科目修改")
        @PutMapping("/update")
        public Object update(@RequestBody Course course){
            if(course != null){
                return this.courseService.update(course);
            }
            return ResponseUtil.result(500, "Fail to update");
        }*/

//    @RequiresPermissions("ADMIN:COURSE:SAVE")
    @PostMapping("/save")
    @ApiOperation("科目添加")
    public Object save(@RequestBody CourseDto courseDto){
        if(courseDto != null){
            return this.courseService.save(courseDto);
        }
        return ResponseUtil.result(500, "Fail to create");
    }

//    @RequiresPermissions("ADMIN:COURSE:DELETE")
    @ApiOperation("科目删除")
    @DeleteMapping("/delete")
    public Object delete(Long id){
        Course course = this.courseService.getObjById(id);
        if(course != null) {
            // 清除关联项
            Map map = new HashMap();
            map.put("course_id", course.getId());
            map.put("currentPage", 0);
            map.put("pageSize", 0);
            List<Video> videoList = this.videoService.findObjByMap(map);
            for(Video video : videoList){
                video.setCourse(null);
                this.videoService.update(video);
            }
            List<RoomProgram> roomProgramList = this.roomProgramService.findObjByCondition(map);

            for(RoomProgram roomProgram : roomProgramList){
                roomProgram.setCourse(null);
                roomProgram.setCourseName(null);
                this.roomProgramService.update(roomProgram);
            }
            if (this.courseService.delete(id)) {
                return ResponseUtil.ok();
            }
        }
        return ResponseUtil.result(500, "Fail to delete");
    }

//    @RequiresPermissions("ADMIN:COURSE:CHANGE")
    @ApiOperation("科目修改")
    @PutMapping("/change")
    public Object change(@RequestBody CourseReq req){
        if(req.getId() != null && !req.getId().equals("")){
            Course course = this.courseService.getObjById(req.getId());
            int display = course.getDisplay() == 1 ? 0 : 1;
            course.setDisplay(display);
            if(course != null){
                this.courseService.update(course);
                return ResponseUtil.ok();
            }
        }
        return ResponseUtil.badArgument();
    }
}
