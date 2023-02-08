package com.metoo.nspm.core.manager.admin.action;

import com.metoo.nspm.core.service.nspm.IAccessoryService;
import com.metoo.nspm.core.service.nspm.ISysConfigService;
import com.metoo.nspm.core.utils.ResponseUtil;
import com.metoo.nspm.entity.nspm.Accessory;
import com.metoo.nspm.entity.nspm.SysConfig;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * <p>
 *     Description：
 *      avi：AVI这个由微软公司发布-的视频格式，在视频领域可以说是最悠久的格式之一。AVI格式调用方便、图像质量好，压缩标准可任意选择，是应用最广泛、也是应用时间最长的格式之一
 *      wmv：一种独立于编码方式的在Internet上实时传播多媒体的技术标准，Microsoft公司希望用其取代QuickTime之类的技术标准以及WAV、AVI之类的文件扩展名。WMV的主要优点在于：可扩充的媒体类型、本地或网络回放、可伸缩的媒体类型、流的优先级化、多语言支持、扩展性等
 *      mpeg：MPEG是包括了MPEG-1,MPEG-2和MPEG-4在内的多种视频格式。MPEG系列标准已成为国际上影响最大的多媒体技术标准，其中MPEG-1和MPEG-2是采用相同原理为基础的预测编码、变换编码、熵编码及运动补偿等第一代数据压缩编码技术；MPEG-4（ISO/IEC 14496）则是基于第二代压缩编码技术制定的国际标准，它以视听媒体对象为基本单元，采用基于内容的压缩编码，以实现数字视音频、图形合成应用及交互式多媒体的集成
 *      mp4：是一套用于音频、视频信息的压缩编码标准,MPEG-4格式的主要用途在于网上流、光盘、语音发送（视频电话），以及电视广播
 *      m4v：M4V是一种应用于网络视频点播网站和移动手持设备的视频格式，是MP4格式的一种特殊类型，其后缀常为.MP4或.M4V，其视频编码采用H264，音频编码采用AAC
 *      mov：MOV即QuickTime影片格式，它是Apple公司开发的一种音频、视频文件格式，用于存储常用数字媒体类型。用于保存音频和视频信息,甚至WINDOWS7在内的所有主流电脑平台支持
 *      asf：ASF 是MICROSOFT 为了和的Real player 竞争而发展出来的一种可以直接在网上观看视频节目的文件压缩格式。ASF使用了MPEG4 的压缩算法，压缩率和图像的质量都很不错。因为，ASF 是以一个可以在网上即时观赏的视频“流”格式存在的，所以，它的图像质量比VCD 差一点点并不出奇，但比同是视频“流”格式的RAM 格式要好
 *      flv：FLV是FLASH VIDEO的简称，FLV流媒体格式是一种新的视频格式。由于它形成的文件极小、加载速度极快，使得网络观看视频文件成为可能，它的出现有效地解决了视频文件导入Flash后，使导出的SWF文件体积庞大，不能在网络上很好的使用等缺点
 *      F4V：F4V作为一种更小更清晰，更利于在网络传播的格式，F4V已经逐渐取代了传统FLV，也已经被大多数主流播放器兼容播放，而不需要通过转换等复杂的方式。F4V是Adobe公司为了迎接高清时代而推出继FLV格式后的支持H.264的F4V流媒体格式。它和FLV主要的区别在于，FLV格式采用的是H263编码，而F4V则支持H.264编码的高清晰视频，码率最高可达50Mbps。也就是说F4V和FLV在同等体积的前提下，能够实现更高的分辨率，并支持更高比特率，就是我们所说的更清晰更流畅。另外，很多主流媒体网站上下载的F4V文件后缀却为FLV，这是F4V格式的另一个特点，属正常现象，观看时可明显感觉到这种实为F4V的FLV有明显更高的清晰度和流畅度
 *      rm：RM格式是RealNetworks公司开发的一种流媒体视频文件格式，可以根据网络数据传输的不同速率制定不同的压缩比率，从而实现低速率的Internet上进行视频文件的实时传送和播放
 *      rmvb：RMVB是一种视频文件格式，其中的VB指Variable Bit Rate（可变比特率）。较上一代RM格式画面要清晰很多，原因是降低了静态画面下的比特率
 *      3gp：3GP是一种3G流媒体的视频编码格式，主要是为了配合3G网络的高传输速度而开发的，也是目前手机中最为常见的一种视频格式
 *      vob：VOB是DVD视频媒体使用的容器格式，VOB将数字视频、数字音频、字幕、DVD菜单和导航等多种内容复用在一个流格式中。VOB格式中的文件可以被加密保护
 *
 *
 * </p>
 */
@Api("文件管理")
@RestController
@RequestMapping("/admin/file")
public class FileUploadManagerController {

    @Autowired
    private IAccessoryService accessoryService;
    @Autowired
    private ISysConfigService configService;

    @ApiOperation("图片上传")
    @RequestMapping("/photo/upload")
    public Object photo(@RequestParam(value = "file", required = false) MultipartFile file){
       /* FileNameMap fileNameMap = URLConnection.getFileNameMap();
        String type = fileNameMap.getContentTypeFor(file.getName());
        return type;*/
        Map data = this.upload(file, 0);
        if(data.get("accessory") != null){
            Map map =  new HashMap();
            Accessory accessory = (Accessory) data.get("accessory");
            map.put("id", accessory.getId());
            return ResponseUtil.ok(map);
        }
        return ResponseUtil.badArgument((String) data.get("msg"));
    }

    @ApiOperation("视频上传")
    @RequestMapping("/video/upload")
    public Object upload(@RequestParam(value = "file", required = false) MultipartFile file){
       /* FileNameMap fileNameMap = URLConnection.getFileNameMap();
        String type = fileNameMap.getContentTypeFor(file.getName());
        return type;*/
        Map data = this.upload(file, 1);
        if(data.get("accessory") != null){
            Map map =  new HashMap();
            Accessory accessory = (Accessory) data.get("accessory");
            map.put("id", accessory.getId());
            return ResponseUtil.ok(map);
        }
        return ResponseUtil.badArgument((String) data.get("msg"));
    }



    public Map upload(@RequestParam(required = false) MultipartFile file, int type){
        Map map = new HashMap();
        SysConfig configs = this.configService.select();
        String uploaFilePath = configs.getUploadFilePath();
        String path = configs.getVideoFilePath();
        String originalName = file.getOriginalFilename();
        String fileName = UUID.randomUUID().toString().replace("-", "");
        String ext = originalName.substring(originalName.lastIndexOf("."));
        String picNewName = fileName + ext;
        boolean flag = false;
        if(ext != null){
            if(type == 0){
                // 判断图片后缀
                String[] extendes = new String[] { "jpg", "jpeg", "gif", "bmp", "tbi", "png" };
                for(String extend : extendes){
                    if(("." + extend.toLowerCase()).equals(ext.toLowerCase())){
                        flag = true;
                    }
                }
                path = configs.getPhotoFilePath();
                uploaFilePath = uploaFilePath + File.separator + "photo";
            }else{
                // 判断视频后缀
                String[] extendes = new String[] { "wmv", "asf", "asx", "rm", "rmvb", "mpg", "mpeg", "mpe",
                        "mp4", "3gp", "mov", "m4v", "avi", "dat", "mkv", "flv", "vob", "3gp", "mov" };
                for(String extend : extendes){
                    if(("." + extend.toLowerCase()).equals(ext)){
                        flag = true;
                    }
                }
                uploaFilePath = uploaFilePath + File.separator + "video";
            }
            String imgRealPath = path + File.separator + picNewName;
            if(flag){
                java.io.File imageFile = new File(imgRealPath);
                if (!imageFile.getParentFile().exists() && !imageFile.getParentFile().isDirectory()) {
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
                    map.put("accessory", accessory);

                } catch (IOException e) {
                    e.printStackTrace();
                    map.put("msg", "上传失败");
                }
            }else{
                map.put("msg", "不允许的扩展名");
            }
        }else{
            map.put("msg", "不允许的扩展名");
        }

        return map;
    }
}
