package com.metoo.nspm.core.utils.file;

import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.util.UUID;

/**
 * 文件上传，下载，二进制文件转换
 */
@Component
public class FileConverterUtil {

    /**
     * 方式一
     * @param path
     * @param multipartFile
     * @return
     */
    public static boolean upload(String path, MultipartFile multipartFile) {
        path = System.getProperty("user.dir");
        if (multipartFile == null && multipartFile.getSize() <= 0) {
            return false;
        }
        //文件名
        String originalName = multipartFile.getOriginalFilename();
        String fileName = UUID.randomUUID().toString().replace("-", "");
        fileName = fileName + originalName.substring(originalName.lastIndexOf("."));
        path = path + fileName;

        try {
            //保存图片-将multipartFile对象装入image文件中
            File file = new File(path);
            multipartFile.transferTo(file);
        } catch (Exception e) {
            return false;
        }
        return true;
    }
}
