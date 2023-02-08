package com.metoo.nspm.core.video;

import com.metoo.nspm.core.utils.file.FileUtil;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

/**
 * <p>
 * Title: VideoUtil.java
 * </p>
 *
 * <p>
 * Descriprion: 视频工具类；负责合并ts文件，转mp4;
 * </p>
 */
@Component
public class VideoUtil {

    /**
     * 转Mp4
     *
     * @param path 源文件地址
     *             playBack 生成回放文件地址
     */
    public static boolean ConvertMp4(String path, String playback, String name) {
        boolean merge = false;
        try {
            // 合并ts 文件
            merge = FileUtil.merge(path, playback);
            if (merge) {
                String read = playback + File.separator + "merge.ts";
                String writer = playback + File.separator  + name +".mp4";
                // linux
                boolean convert = ChangeVideo.convert(read, writer);  // 转mp4
                if (convert) {
                    // 转换完成，删除merge文件
                    FileUtil.delFile(read);
                }
                return convert;
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return false;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }
}
