package com.metoo.nspm.core.service.nspm.impl;

import com.metoo.nspm.core.mapper.nspm.LiveRoomMapper;
import com.metoo.nspm.core.service.nspm.ILiveRoomService;
import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.dto.LiveRoomDto;
import com.metoo.nspm.entity.nspm.LiveRoom;
import com.metoo.nspm.vo.WebLiveRoomVo;
import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

@Service
@Transactional
public class LiveRoomServiceImpl implements ILiveRoomService {

    @Autowired
    private LiveRoomMapper liveRoomMapper;
    @Autowired
    private ISysConfigService sysConfigService;

    @Override
    public LiveRoom getObjById(Long id) {
        return this.liveRoomMapper.getObjById(id);
    }

    @Override
    public List<LiveRoom> findAllLiveRoom() {
        return this.liveRoomMapper.findAllLiveRoom();
    }

    @Override
    public boolean save(LiveRoom instance) {
        if(instance.getId() == null){
            /*instance.setAddTime(new Date());
            Date date = new Date();
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
            String df = sdf.format(date);
            String bindCode = df + CommUtils.randomString(6);// 推流码
            instance.setBindCode(bindCode);

            User user = ShiroUserHolder.currentUser();
            instance.setUser(user);
            instance.setUserId(user.getId());
            instance.setUsername(user.getUsername());
            if(user.getUserRole().equals("ADMIN")){
                instance.setType(1);
            }
            if(instance.getTitle() == null || instance.getTitle().equals("")){
                instance.setTitle("默认直播间");
            }
            if(instance.getManager() == null || instance.getManager().equals("")){
                instance.setManager(user.getUsername());
            }
            //rtmp://lk.soarmall.com:1935/hls
            SysConfig SysConfig = this.sysConfigService.findSysConfigList();
            String rtmp = CommUtils.getRtmp(SysConfig.getIp(), bindCode);
            String obsRtmp = CommUtils.getObsRtmp(SysConfig.getIp());
            String path =  SysConfig.getPath() + File.separator + bindCode;
            instance.setRtmp(rtmp);
            instance.setObsRtmp(obsRtmp);
            try {
                FileUtil.storeFile(path);
                FileUtil.possessor(path);
            } catch (IOException e) {
                e.printStackTrace();
            }
*/
            try {
                this.liveRoomMapper.save(instance);
                return true;
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }else{
            try {
                this.liveRoomMapper.update(instance);
                return true;
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }
    }

    @Override
    public int update(LiveRoom instance) {
        return this.liveRoomMapper.update(instance);
    }

    @Override
    public int delete(Long id) {
        return this.liveRoomMapper.delete(id);
    }

    @Override
    public List<LiveRoom> findObjByMap(Map<String, Object> params) {
        Page<LiveRoom> page = PageHelper.startPage((Integer)params.get("currentPage"), (Integer)params.get("pageSize"));
        return this.liveRoomMapper.findObjByMap(params);
    }

    @Override
    public Page<LiveRoom> query(LiveRoomDto dto) {
        Page<LiveRoom> page = PageHelper.startPage(dto.getCurrentPage(), dto.getPageSize());
        this.liveRoomMapper.query(dto);
        return page;
    }


    @Override
    public int findAccountByTotal() {
        return this.liveRoomMapper.getAccountByTotal();
    }

    @Override
    public int modify(String property) {
        return this.liveRoomMapper.change(property);
    }

    /**
     * pageHelper
     * @return
     */
    @Override
    public List<LiveRoom> queryLiveRooms(Integer currentPage, Integer pageSize) {
      /*  PageHelper.startPage(currentPage, pageSize);
        List<LiveRoom> liveRoomList = this.liveRoomMapper.selectAll();
        //将查询到的数据封装到PageInfo对象
        PageInfo<LiveRoom> pageInfo = new PageInfo(liveRoomList, pageSize);
        return liveRoomList;*/

        // 分页插件: 查询第1页，每页10行
        Page<LiveRoom> page = PageHelper.startPage(currentPage, pageSize);
        this.liveRoomMapper.selectAll();
        // 数据表的总行数
        page.getTotal();
        // 分页查询结果的总行数
        page.size();
        // 第一个User对象，参考list，序号0是第一个元素，依此类推
        //page.get(0);

        //测试PageInfo全部属性
//        SystemTest.out.println(page.getPageNum());
//        SystemTest.out.println(page.getPageSize());
//        SystemTest.out.println(page.getStartRow());
//        SystemTest.out.println(page.getEndRow());
//        SystemTest.out.println(page.getTotal());
//        SystemTest.out.println(page.getPages());
//        SystemTest.out.println(page.getFirstPage());
//        SystemTest.out.println(page.getLastPage());
//        SystemTest.out.println(page.isHasPreviousPage());
//        SystemTest.out.println(page.isHasNextPage());

        return page;
    }

    @Override
    public Page<WebLiveRoomVo> webLiveRoom(Map<String, Object> params) {
        Page<WebLiveRoomVo> page = PageHelper.startPage((Integer)params.get("currentPage"), (Integer)params.get("pageSize"));
        this.liveRoomMapper.webLiveRoom(params);
        // 数据表的总行数
        page.getTotal();
        // 分页查询结果的总行数
        page.size();
        return page;
    }
}
