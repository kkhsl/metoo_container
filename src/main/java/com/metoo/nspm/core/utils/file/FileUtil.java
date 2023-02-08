package com.metoo.nspm.core.utils.file;

import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.*;

/**
 * <p>
 *     Title: FileUtil.java
 * </p>
 *
 * <p>
 *     Desciption: 文件工具管理类；
 *        负责创建文件
 *       文件夹权限修改等;
 * </p>
 *
 * <author>
 *     HKK
 * </author>
 */

@Component
public class FileUtil {

    /**
     * m3u8转mp4
     *
     * @param path
     * @return
     */
    public static boolean merge(String path, String playBack) throws FileNotFoundException {
        boolean flag = true;
        File file = new File(path);
        if (!file.exists()) {
            return false;
        }
        LinkedList<Integer> tsList = getTsNumber(file);
        if (tsList != null && tsList.size() > 0) {
            File playBackFile = new File(playBack);
            if (!playBackFile.exists() && !playBackFile.isDirectory()) {
                playBackFile.mkdirs();
            }
            String mergeFile = playBack + File.separator + "merge.ts";
            BufferedInputStream bis = null;
            Collections.sort(tsList);
            BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(mergeFile));

            for (Integer ts : tsList) {
                try {
                    bis = new BufferedInputStream(new FileInputStream(path + File.separator + ts + ".ts"));
                    byte[] bytes = new byte[1024];
                    int len = 0;
                    while ((len = bis.read(bytes)) > 0) {
                        bos.write(bytes, 0, len);
                        bos.flush();
                    }
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                    throw new RuntimeException("第" + ts + "次循环IO流异常");
                }
            }
            // 删除原文件所有.ts文件、m3u8文件
            try {
                boolean delFlag = delFileTs(path);
                String m3u8 = path + File.separator + "index.m3u8";
                delFile(m3u8);
            } catch (Exception e) {
                e.printStackTrace();
            }

        } else {
            return false;
        }
        return flag;
    }

    /**
     * 遍历目录下所有.ts文件
     *
     * @param file
     * @return
     */
    public static LinkedList<Integer> getTsNumber(File file) {
        File[] listFiles = file.listFiles();
        LinkedList<Integer> list = new LinkedList<>();
        for (File f : listFiles) {
            if (f.getName().endsWith(".ts")) {
                //fileName.substring(0, fileName.lastIndexOf("."));
                list.add(Integer.parseInt(f.getName().substring(0, f.getName().lastIndexOf("."))));
            }
        }
        return list;
    }

    /**
     * 删除文件
     * 删除当前目录下所有.ts文件 文件分片
     *
     * @param path
     * @return
     */
    public static boolean delFileTs(String path) {
        File file = new File(path);
        if (!file.exists() && !file.isDirectory()) {
            return false;
        }
        File[] files = file.listFiles();
        for (File f : files) {
            if (f.getName().endsWith(".ts")) {
                if (f.isFile() && file.exists()) {
                    f.delete();
                }
            }
        }
        return true;
    }

    // 删除垃圾文件
    public static void delFile(String path) {
        File file = new File(path);
        try {
            if (file.exists() && file.isFile()) {
                file.delete();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void deleteAll(File file) {
        if (file.isFile() || file.list().length == 0) {
            file.delete();
        }else{
            for (File f : file.listFiles()) {
                deleteAll(f); // 递归删除每一个文件
            }
            file.delete(); // 删除文件夹
        }



        try {

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    /**
     * 修改目录权限 off
     *
     * @param filePath
     * @throws IllegalStateException
     * @throws IOException
     */
    public static void storeFile(String filePath) throws IllegalStateException, IOException {
        File file = new File(filePath);
        if(!file.isDirectory() ){
            file.mkdirs();
        }

        //设置权限
        Set<PosixFilePermission> perms = new HashSet<PosixFilePermission>();
        perms.add(PosixFilePermission.OWNER_READ);//设置所有者的读取权限
      /*  perms.add(PosixFilePermission.OWNER_WRITE);//设置所有者的写权限
        perms.add(PosixFilePermission.OWNER_EXECUTE);//设置所有者的执行权限*/
/*        perms.add(PosixFilePermission.GROUP_READ);//设置组的读取权限
        perms.add(PosixFilePermission.GROUP_EXECUTE);//设置组的读取权限
        perms.add(PosixFilePermission.OTHERS_READ);//设置其他的读取权限
        perms.add(PosixFilePermission.OTHERS_EXECUTE);//设置其他的读取权限*/
        try {
            //设置文件和文件夹的权限
            Path pathParent = Paths.get(file.getAbsolutePath());
            Files.setPosixFilePermissions(pathParent, perms);//修改文件夹路径的权限

            //Runtime.getRuntime().exec("chown -R www:www " + filePath);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void storeFileOpen(String filePath) throws IllegalStateException, IOException {
        File file = new File(filePath);
        //设置权限
        Set<PosixFilePermission> perms = new HashSet<PosixFilePermission>();
        perms.add(PosixFilePermission.OWNER_READ);//设置所有者的读取权限
        perms.add(PosixFilePermission.OWNER_WRITE);//设置所有者的写权限
        perms.add(PosixFilePermission.OWNER_EXECUTE);
        try {
            /*perms.add(PosixFilePermission.OWNER_EXECUTE);//设置所有者的执行权限*/
            perms.add(PosixFilePermission.GROUP_READ);//设置组的读取权限
            /*perms.add(PosixFilePermission.GROUP_EXECUTE);//设置组的读取权限*/
            perms.add(PosixFilePermission.OTHERS_READ);//设置其他的读取权限
            /*perms.add(PosixFilePermission.OTHERS_EXECUTE);//设置其他的执行权限*/
            //设置文件和文件夹的权限
            Path pathParent = Paths.get(file.getAbsolutePath());
            Files.setPosixFilePermissions(pathParent, perms);//修改文件夹路径的权限
            //Runtime.getRuntime().exec("chown -R www:www " + filePath);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 修改文件/目录所有者
     */
    public static void possessor(String object){
        Path path = Paths.get(object);
        FileOwnerAttributeView foav = Files.getFileAttributeView(path,
                FileOwnerAttributeView.class);
        try {
            UserPrincipal owner = foav.getOwner();
            UserPrincipalLookupService upls = FileSystems.getDefault().getUserPrincipalLookupService();

            UserPrincipal newOwner = upls.lookupPrincipalByName("www");
            foav.setOwner(newOwner);

            UserPrincipal changedOwner = foav.getOwner();

        } catch (IOException e) {
            e.printStackTrace();
        }

    }
    /**
     * 修改文件/目录所有组
     */
    public static void groups(){

    }

    /**
     * 上传路径， 上传文件
     *
     * @param path          文件保存路径
     * @param multipartFile 上传文件
     */

    public static boolean imageUpload(String path, MultipartFile multipartFile) {
        path = System.getProperty("user.dir");
        if (multipartFile == null && multipartFile.getSize() <= 0) {
            return false;
        }
        //文件名
        String originalName = multipartFile.getOriginalFilename();
        String fileName = UUID.randomUUID().toString().replace("-", "");
        String picNewName = fileName + originalName.substring(originalName.lastIndexOf("."));
        String imgRealPath = path + picNewName;

        try {
            //保存图片-将multipartFile对象装入image文件中
            File imageFile = new File(imgRealPath);
            multipartFile.transferTo(imageFile);
        } catch (Exception e) {
            return false;
        }
        return true;
    }
}
